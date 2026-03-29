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
        },
        {
            "name": "ewf_list_sections",
            "description": "List all section descriptors in the E01 image. Shows the internal structure: headers, volume, tables, sectors, hash, digest, done sections with their offsets and sizes.",
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
            "name": "ewf_search",
            "description": "Search for a byte pattern (hex string) in the disk image. Returns up to max_results matching offsets.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the first segment file (e.g. image.E01)"
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Hex string to search for (e.g. '55aa' for MBR signature)"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of matches to return (default: 10, max: 100)"
                    }
                },
                "required": ["path", "pattern"]
            }
        },
        {
            "name": "ewf_extract",
            "description": "Extract a byte range from the disk image and write it to a file.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the first segment file (e.g. image.E01)"
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Byte offset to start extracting from"
                    },
                    "length": {
                        "type": "integer",
                        "description": "Number of bytes to extract"
                    },
                    "output": {
                        "type": "string",
                        "description": "Path to write the extracted bytes to"
                    }
                },
                "required": ["path", "offset", "length", "output"]
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

pub fn handle_ewf_list_sections(path: &str) -> Result<Value, String> {
    use std::io::{Read, Seek, SeekFrom};
    use std::path::Path;

    // Discover segment files using glob (same pattern as ewf crate internals).
    let first = Path::new(path);
    let stem = first.file_stem().and_then(|s| s.to_str())
        .ok_or_else(|| format!("cannot extract stem from: {path}"))?;
    let parent = first.parent().unwrap_or_else(|| Path::new("."));
    let escaped_stem = glob::Pattern::escape(stem);
    let parent_str = parent.display();

    let mut seg_paths: Vec<std::path::PathBuf> = Vec::new();
    for pattern in &[
        format!("{parent_str}/{escaped_stem}.[Ee][0-9][0-9]"),
        format!("{parent_str}/{escaped_stem}.[Ee][A-Za-z][A-Za-z]"),
    ] {
        if let Ok(entries) = glob::glob(pattern) {
            seg_paths.extend(entries.filter_map(|r| r.ok()));
        }
    }
    if seg_paths.is_empty() {
        return Err(format!("no EWF segments found for: {path}"));
    }
    seg_paths.sort_by(|a, b| {
        let ea = a.extension().and_then(|e| e.to_str()).unwrap_or("");
        let eb = b.extension().and_then(|e| e.to_str()).unwrap_or("");
        ea.to_ascii_uppercase().cmp(&eb.to_ascii_uppercase())
    });

    let mut all_sections = Vec::new();

    for (seg_idx, seg_path) in seg_paths.iter().enumerate() {
        let mut file = std::fs::File::open(seg_path).map_err(|e| format!("{e}"))?;
        let file_len = file.seek(SeekFrom::End(0)).map_err(|e| format!("{e}"))?;
        let mut offset: u64 = 13; // skip 13-byte file header

        loop {
            if offset + 76 > file_len {
                break;
            }
            file.seek(SeekFrom::Start(offset)).map_err(|e| format!("{e}"))?;
            let mut buf = [0u8; 76];
            file.read_exact(&mut buf).map_err(|e| format!("{e}"))?;
            let desc = ewf::SectionDescriptor::parse(&buf, offset).map_err(|e| format!("{e}"))?;

            all_sections.push(json!({
                "segment": seg_idx,
                "type": desc.section_type,
                "offset": desc.offset,
                "size": desc.section_size,
            }));

            if desc.next == 0 || desc.next <= offset {
                break;
            }
            offset = desc.next;
        }
    }

    Ok(json!({ "sections": all_sections }))
}

pub fn handle_ewf_search(path: &str, pattern_hex: &str, max_results: usize) -> Result<Value, String> {
    use std::io::{Read, Seek, SeekFrom};

    // Parse hex pattern
    if pattern_hex.len() % 2 != 0 {
        return Err("hex pattern must have even length (each byte is 2 hex chars)".into());
    }
    let pattern: Vec<u8> = (0..pattern_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&pattern_hex[i..i + 2], 16))
        .collect::<std::result::Result<Vec<u8>, _>>()
        .map_err(|e| format!("invalid hex pattern: {e}"))?;

    if pattern.is_empty() {
        return Err("pattern must not be empty".into());
    }

    let mut reader = ewf::EwfReader::open(path).map_err(|e| format!("{e}"))?;
    let total = reader.total_size();
    reader.seek(SeekFrom::Start(0)).map_err(|e| format!("{e}"))?;

    let mut matches = Vec::new();
    let buf_size = 64 * 1024; // 64 KB read buffer
    let mut buf = vec![0u8; buf_size + pattern.len() - 1]; // overlap for cross-boundary matches
    let mut file_offset: u64 = 0;
    let mut carry = 0usize; // bytes carried over from previous read

    while file_offset < total && matches.len() < max_results {
        let to_read = buf_size.min((total - file_offset) as usize);
        let n = reader.read(&mut buf[carry..carry + to_read]).map_err(|e| format!("{e}"))?;
        if n == 0 {
            break;
        }
        let search_len = carry + n;

        // Search for pattern in buffer
        let end = if search_len >= pattern.len() { search_len - pattern.len() + 1 } else { 0 };
        for i in 0..end {
            if buf[i..i + pattern.len()] == pattern[..] {
                let match_offset = file_offset - carry as u64 + i as u64;
                matches.push(json!({ "offset": match_offset }));
                if matches.len() >= max_results {
                    break;
                }
            }
        }

        // Carry over the tail for cross-boundary matching
        if pattern.len() > 1 && search_len >= pattern.len() - 1 {
            let overlap = pattern.len() - 1;
            buf.copy_within(search_len - overlap..search_len, 0);
            carry = overlap;
        } else {
            carry = 0;
        }
        file_offset += n as u64;
    }

    Ok(json!({
        "pattern": pattern_hex,
        "matches": matches,
        "total_found": matches.len(),
    }))
}

pub fn handle_ewf_extract(path: &str, offset: u64, length: u64, output: &str) -> Result<Value, String> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut reader = ewf::EwfReader::open(path).map_err(|e| format!("{e}"))?;
    let total = reader.total_size();
    if offset >= total {
        return Err(format!("offset {offset} exceeds media size {total}"));
    }
    let actual_len = length.min(total - offset);
    reader.seek(SeekFrom::Start(offset)).map_err(|e| format!("{e}"))?;

    let mut outfile = std::fs::File::create(output).map_err(|e| format!("{e}"))?;
    let mut remaining = actual_len;
    let mut buf = vec![0u8; 64 * 1024];

    while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len());
        let n = reader.read(&mut buf[..to_read]).map_err(|e| format!("{e}"))?;
        if n == 0 {
            break;
        }
        outfile.write_all(&buf[..n]).map_err(|e| format!("{e}"))?;
        remaining -= n as u64;
    }

    Ok(json!({
        "offset": offset,
        "bytes_written": actual_len - remaining,
        "output": output,
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
        "ewf_list_sections" => {
            let path = args.get("path").and_then(|v| v.as_str())
                .ok_or("missing required parameter: path")?;
            handle_ewf_list_sections(path)
        }
        "ewf_search" => {
            let path = args.get("path").and_then(|v| v.as_str())
                .ok_or("missing required parameter: path")?;
            let pattern = args.get("pattern").and_then(|v| v.as_str())
                .ok_or("missing required parameter: pattern")?;
            let max = args.get("max_results").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
            let max = max.min(100);
            handle_ewf_search(path, pattern, max)
        }
        "ewf_extract" => {
            let path = args.get("path").and_then(|v| v.as_str())
                .ok_or("missing required parameter: path")?;
            let offset = args.get("offset").and_then(|v| v.as_u64())
                .ok_or("missing required parameter: offset")?;
            let length = args.get("length").and_then(|v| v.as_u64())
                .ok_or("missing required parameter: length")?;
            let output = args.get("output").and_then(|v| v.as_str())
                .ok_or("missing required parameter: output")?;
            handle_ewf_extract(path, offset, length, output)
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

    // --- ewf_list_sections ---

    #[test]
    fn list_sections_returns_expected_types() {
        let path = format!("{DATA_DIR}/exfat1.E01");
        let result = handle_ewf_list_sections(&path).unwrap();
        let sections = result["sections"].as_array().unwrap();
        assert!(!sections.is_empty());
        // exfat1.E01 has: header2, header2, header, volume, sectors, table, table2, data, hash, done
        let types: Vec<&str> = sections.iter()
            .map(|s| s["type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"volume"), "should contain volume section");
        assert!(types.contains(&"hash"), "should contain hash section");
        assert!(types.contains(&"done"), "should contain done section");
    }

    #[test]
    fn list_sections_includes_offsets_and_sizes() {
        let path = format!("{DATA_DIR}/exfat1.E01");
        let result = handle_ewf_list_sections(&path).unwrap();
        let first = &result["sections"][0];
        assert!(first.get("offset").is_some(), "section should have offset");
        assert!(first.get("size").is_some(), "section should have size");
        assert!(first.get("type").is_some(), "section should have type");
    }

    // --- ewf_search ---

    #[test]
    fn search_finds_mbr_signature() {
        // imageformat_mmls_1.E01 has MBR signature 55AA at offset 510
        let path = format!("{DATA_DIR}/imageformat_mmls_1.E01");
        let result = handle_ewf_search(&path, "55aa", 100).unwrap();
        let matches = result["matches"].as_array().unwrap();
        assert!(!matches.is_empty(), "should find at least one 55aa");
        // Offset 510 (MBR signature) must be among the matches
        let offsets: Vec<u64> = matches.iter()
            .map(|m| m["offset"].as_u64().unwrap())
            .collect();
        assert!(offsets.contains(&510), "should find 55aa at MBR offset 510, got offsets: {offsets:?}");
    }

    #[test]
    fn search_returns_empty_for_nonexistent_pattern() {
        let path = format!("{DATA_DIR}/nps-2010-emails.E01");
        // Search for a pattern unlikely to exist
        let result = handle_ewf_search(&path, "deadbeefcafebabe", 10).unwrap();
        let matches = result["matches"].as_array().unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn search_respects_max_results() {
        let path = format!("{DATA_DIR}/exfat1.E01");
        // Search for 0x00 which will appear everywhere — limit to 3
        let result = handle_ewf_search(&path, "00", 3).unwrap();
        let matches = result["matches"].as_array().unwrap();
        assert!(matches.len() <= 3);
    }

    // --- ewf_extract ---

    #[test]
    fn extract_writes_correct_bytes() {
        let path = format!("{DATA_DIR}/imageformat_mmls_1.E01");
        let output = format!("{DATA_DIR}/../extract_test.bin");
        let result = handle_ewf_extract(&path, 510, 2, &output).unwrap();
        assert_eq!(result["bytes_written"], 2);
        // Verify the file contains MBR signature
        let data = std::fs::read(&output).unwrap();
        assert_eq!(data, vec![0x55, 0xAA]);
        std::fs::remove_file(&output).unwrap();
    }

    #[test]
    fn extract_clamps_to_media_size() {
        let path = format!("{DATA_DIR}/nps-2010-emails.E01");
        let output = format!("{DATA_DIR}/../extract_clamp_test.bin");
        // Request more bytes than remain
        let result = handle_ewf_extract(&path, 10_485_750, 100, &output).unwrap();
        // Only 10 bytes remain (10_485_760 - 10_485_750)
        assert_eq!(result["bytes_written"], 10);
        std::fs::remove_file(&output).unwrap();
    }

    #[test]
    fn search_rejects_odd_length_hex() {
        let path = format!("{DATA_DIR}/nps-2010-emails.E01");
        // "ABC" is 3 chars — odd length, not a valid hex byte sequence
        let result = handle_ewf_search(&path, "ABC", 10);
        assert!(result.is_err(), "Odd-length hex should return Err, not panic");
    }

    #[test]
    fn search_rejects_empty_hex() {
        let path = format!("{DATA_DIR}/nps-2010-emails.E01");
        let result = handle_ewf_search(&path, "", 10);
        assert!(result.is_err(), "Empty hex should return Err");
    }
}
