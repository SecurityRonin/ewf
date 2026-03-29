use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

fn tool_definitions() -> Value {
    json!([
        {
            "name": "ewf_info",
            "description": "Open an E01 image and return metadata: media size, chunk geometry, stored hashes, case info, and acquisition errors.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the first segment file (e.g. image.E01)"
                    }
                },
                "required": ["path"]
            }
        },
        {
            "name": "ewf_verify",
            "description": "Verify E01 image integrity by recomputing MD5/SHA-1 and comparing against stored hashes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the first segment file (e.g. image.E01)"
                    }
                },
                "required": ["path"]
            }
        },
        {
            "name": "ewf_read_sectors",
            "description": "Read raw bytes from the disk image at a given offset. Returns hex dump.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the first segment file (e.g. image.E01)"
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Byte offset to start reading from (default: 0)"
                    },
                    "length": {
                        "type": "integer",
                        "description": "Number of bytes to read (default: 512, max: 4096)"
                    }
                },
                "required": ["path"]
            }
        }
    ])
}

// ---------------------------------------------------------------------------
// Tool handlers (pure functions, independently testable)
// ---------------------------------------------------------------------------

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn handle_ewf_info(path: &str) -> Result<Value, String> {
    let reader = ewf::EwfReader::open(path).map_err(|e| format!("{e}"))?;
    let hashes = reader.stored_hashes();
    let meta = reader.metadata();
    let errors = reader.acquisition_errors();

    Ok(json!({
        "media_size": reader.total_size(),
        "chunk_size": reader.chunk_size(),
        "chunk_count": reader.chunk_count(),
        "stored_hashes": {
            "md5": hashes.md5.map(|h| hex_string(&h)),
            "sha1": hashes.sha1.map(|h| hex_string(&h)),
        },
        "metadata": {
            "case_number": meta.case_number,
            "evidence_number": meta.evidence_number,
            "description": meta.description,
            "examiner": meta.examiner,
            "notes": meta.notes,
            "acquiry_software": meta.acquiry_software,
            "os_version": meta.os_version,
            "acquiry_date": meta.acquiry_date,
            "system_date": meta.system_date,
        },
        "acquisition_errors": errors.iter().map(|e| json!({
            "first_sector": e.first_sector,
            "sector_count": e.sector_count,
        })).collect::<Vec<_>>(),
    }))
}

pub fn handle_ewf_verify(path: &str) -> Result<Value, String> {
    let mut reader = ewf::EwfReader::open(path).map_err(|e| format!("{e}"))?;
    let result = reader.verify().map_err(|e| format!("{e}"))?;

    Ok(json!({
        "computed_md5": hex_string(&result.computed_md5),
        "computed_sha1": result.computed_sha1.map(|h| hex_string(&h)),
        "md5_match": result.md5_match,
        "sha1_match": result.sha1_match,
    }))
}

pub fn handle_ewf_read_sectors(path: &str, offset: u64, length: usize) -> Result<Value, String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut reader = ewf::EwfReader::open(path).map_err(|e| format!("{e}"))?;
    let total = reader.total_size();
    if offset >= total {
        return Err(format!("offset {offset} exceeds media size {total}"));
    }
    let actual_len = length.min((total - offset) as usize);
    reader.seek(SeekFrom::Start(offset)).map_err(|e| format!("{e}"))?;
    let mut buf = vec![0u8; actual_len];
    reader.read_exact(&mut buf).map_err(|e| format!("{e}"))?;

    Ok(json!({
        "offset": offset,
        "length": actual_len,
        "hex": hex_string(&buf),
    }))
}

// ---------------------------------------------------------------------------
// MCP protocol (JSON-RPC over stdio)
// ---------------------------------------------------------------------------

fn dispatch_tool(name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "ewf_info" => {
            let path = args.get("path").and_then(|v| v.as_str())
                .ok_or("missing required parameter: path")?;
            handle_ewf_info(path)
        }
        "ewf_verify" => {
            let path = args.get("path").and_then(|v| v.as_str())
                .ok_or("missing required parameter: path")?;
            handle_ewf_verify(path)
        }
        "ewf_read_sectors" => {
            let path = args.get("path").and_then(|v| v.as_str())
                .ok_or("missing required parameter: path")?;
            let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
            let length = args.get("length").and_then(|v| v.as_u64()).unwrap_or(512) as usize;
            let length = length.min(4096);
            handle_ewf_read_sectors(path, offset, length)
        }
        _ => Err(format!("unknown tool: {name}")),
    }
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.is_empty() {
            continue;
        }

        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": format!("Parse error: {e}")},
                    "id": null
                });
                let _ = writeln!(stdout, "{err}");
                continue;
            }
        };

        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "ewf-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                },
                "id": id
            }),
            "notifications/initialized" => continue,
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "result": { "tools": tool_definitions() },
                "id": id
            }),
            "tools/call" => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));

                match dispatch_tool(tool_name, &args) {
                    Ok(result) => json!({
                        "jsonrpc": "2.0",
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                            }]
                        },
                        "id": id
                    }),
                    Err(e) => json!({
                        "jsonrpc": "2.0",
                        "result": {
                            "content": [{"type": "text", "text": e}],
                            "isError": true
                        },
                        "id": id
                    }),
                }
            }
            _ => json!({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": format!("Method not found: {method}")},
                "id": id
            }),
        };

        let _ = writeln!(stdout, "{response}");
        let _ = stdout.flush();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../ewf/tests/data");

    #[test]
    fn ewf_info_returns_media_size() {
        let path = format!("{DATA_DIR}/exfat1.E01");
        let result = handle_ewf_info(&path).unwrap();
        assert_eq!(result["media_size"], 100_020_736);
    }

    #[test]
    fn ewf_info_returns_stored_md5() {
        let path = format!("{DATA_DIR}/exfat1.E01");
        let result = handle_ewf_info(&path).unwrap();
        assert_eq!(
            result["stored_hashes"]["md5"].as_str().unwrap(),
            "0777ee90c27ed5ff5868af2015bed635"
        );
    }

    #[test]
    fn ewf_info_returns_case_metadata() {
        let path = format!("{DATA_DIR}/imageformat_mmls_1.E01");
        let result = handle_ewf_info(&path).unwrap();
        assert_eq!(result["metadata"]["case_number"], "1");
        assert_eq!(result["metadata"]["examiner"], "Rishwanth");
    }

    #[test]
    fn ewf_verify_returns_match_status() {
        let path = format!("{DATA_DIR}/exfat1.E01");
        let result = handle_ewf_verify(&path).unwrap();
        assert_eq!(result["md5_match"], true);
    }

    #[test]
    fn ewf_verify_returns_computed_md5() {
        let path = format!("{DATA_DIR}/exfat1.E01");
        let result = handle_ewf_verify(&path).unwrap();
        assert_eq!(
            result["computed_md5"].as_str().unwrap(),
            "0777ee90c27ed5ff5868af2015bed635"
        );
    }

    #[test]
    fn ewf_read_sectors_returns_hex_data() {
        let path = format!("{DATA_DIR}/imageformat_mmls_1.E01");
        let result = handle_ewf_read_sectors(&path, 510, 2).unwrap();
        // MBR signature at offset 510-511 is 55 AA
        assert_eq!(result["hex"].as_str().unwrap(), "55aa");
    }

    #[test]
    fn ewf_read_sectors_default_512_bytes() {
        let path = format!("{DATA_DIR}/exfat1.E01");
        let result = handle_ewf_read_sectors(&path, 0, 512).unwrap();
        let hex = result["hex"].as_str().unwrap();
        assert_eq!(hex.len(), 1024); // 512 bytes = 1024 hex chars
    }

    #[test]
    fn ewf_info_errors_on_bad_path() {
        let result = handle_ewf_info("/nonexistent/image.E01");
        assert!(result.is_err());
    }
}
