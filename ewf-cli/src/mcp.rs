use crate::handlers;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

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

fn dispatch_tool(name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "ewf_info" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or("missing required parameter: path")?;
            handlers::handle_ewf_info(path)
        }
        "ewf_verify" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or("missing required parameter: path")?;
            handlers::handle_ewf_verify(path)
        }
        "ewf_read_sectors" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or("missing required parameter: path")?;
            let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
            let length = args.get("length").and_then(|v| v.as_u64()).unwrap_or(512) as usize;
            let length = length.min(4096);
            handlers::handle_ewf_read_sectors(path, offset, length)
        }
        "ewf_list_sections" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or("missing required parameter: path")?;
            handlers::handle_ewf_list_sections(path)
        }
        "ewf_search" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or("missing required parameter: path")?;
            let pattern = args
                .get("pattern")
                .and_then(|v| v.as_str())
                .ok_or("missing required parameter: pattern")?;
            let max = args
                .get("max_results")
                .and_then(|v| v.as_u64())
                .unwrap_or(10) as usize;
            let max = max.min(100);
            handlers::handle_ewf_search(path, pattern, max)
        }
        "ewf_extract" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or("missing required parameter: path")?;
            let offset = args
                .get("offset")
                .and_then(|v| v.as_u64())
                .ok_or("missing required parameter: offset")?;
            let length = args
                .get("length")
                .and_then(|v| v.as_u64())
                .ok_or("missing required parameter: length")?;
            let output = args
                .get("output")
                .and_then(|v| v.as_str())
                .ok_or("missing required parameter: output")?;
            handlers::handle_ewf_extract(path, offset, length, output)
        }
        _ => Err(format!("unknown tool: {name}")),
    }
}

pub fn run() {
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
                        "name": "ewf",
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
