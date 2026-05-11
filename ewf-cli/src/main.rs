mod handlers;
mod mcp;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ewf",
    version,
    about = "CLI and MCP server for EWF (E01) forensic disk images"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show image metadata: media size, chunk geometry, stored hashes, case info
    Info {
        /// Path to the first segment file (e.g. image.E01)
        path: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Verify image integrity by recomputing MD5/SHA-1 against stored hashes
    Verify {
        /// Path to the first segment file (e.g. image.E01)
        path: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Read raw bytes at a given offset (hex dump)
    Read {
        /// Path to the first segment file (e.g. image.E01)
        path: String,
        /// Byte offset to start reading from
        #[arg(short, long, default_value = "0")]
        offset: u64,
        /// Number of bytes to read (max 4096)
        #[arg(short, long, default_value = "512")]
        length: usize,
    },
    /// List all section descriptors across segments
    Sections {
        /// Path to the first segment file (e.g. image.E01)
        path: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Search for a hex byte pattern in the disk image
    Search {
        /// Path to the first segment file (e.g. image.E01)
        path: String,
        /// Hex string to search for (e.g. 55aa)
        pattern: String,
        /// Maximum number of matches to return
        #[arg(short, long, default_value = "10")]
        max_results: usize,
    },
    /// Extract a byte range to a file
    Extract {
        /// Path to the first segment file (e.g. image.E01)
        path: String,
        /// Byte offset to start extracting from
        #[arg(short, long)]
        offset: u64,
        /// Number of bytes to extract
        #[arg(short, long)]
        length: u64,
        /// Output file path
        #[arg(short = 'O', long)]
        output: String,
    },
    /// Start MCP server (JSON-RPC over stdio) for AI-assisted forensic analysis
    Mcp,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Info { ref path, json } => {
            handlers::handle_ewf_info(path).map(|v| format_output(&v, json, format_info))
        }
        Command::Verify { ref path, json } => {
            handlers::handle_ewf_verify(path).map(|v| format_output(&v, json, format_verify))
        }
        Command::Read {
            ref path,
            offset,
            length,
        } => {
            let length = length.min(4096);
            handlers::handle_ewf_read_sectors(path, offset, length).map(|v| format_hex_dump(&v))
        }
        Command::Sections { ref path, json } => handlers::handle_ewf_list_sections(path)
            .map(|v| format_output(&v, json, format_sections)),
        Command::Search {
            ref path,
            ref pattern,
            max_results,
        } => {
            let max_results = max_results.min(100);
            handlers::handle_ewf_search(path, pattern, max_results).map(|v| format_search(&v))
        }
        Command::Extract {
            ref path,
            offset,
            length,
            ref output,
        } => handlers::handle_ewf_extract(path, offset, length, output).map(|v| format_extract(&v)),
        Command::Mcp => {
            mcp::run();
            return;
        }
    };

    match result {
        Ok(output) => print!("{output}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn format_output(
    value: &serde_json::Value,
    json: bool,
    human_fn: fn(&serde_json::Value) -> String,
) -> String {
    if json {
        serde_json::to_string_pretty(value).unwrap_or_default() + "\n"
    } else {
        human_fn(value)
    }
}

fn format_info(v: &serde_json::Value) -> String {
    let mut out = String::new();

    out.push_str(&format!("Media size:  {} bytes", v["media_size"]));
    let bytes = v["media_size"].as_u64().unwrap_or(0);
    if bytes >= 1024 * 1024 * 1024 {
        out.push_str(&format!(
            " ({:.1} GiB)",
            bytes as f64 / (1024.0 * 1024.0 * 1024.0)
        ));
    } else if bytes >= 1024 * 1024 {
        out.push_str(&format!(" ({:.1} MiB)", bytes as f64 / (1024.0 * 1024.0)));
    }
    out.push('\n');

    out.push_str(&format!("Chunk size:  {} bytes\n", v["chunk_size"]));
    out.push_str(&format!("Chunk count: {}\n", v["chunk_count"]));

    if let Some(md5) = v["stored_hashes"]["md5"].as_str() {
        out.push_str(&format!("Stored MD5:  {md5}\n"));
    }
    if let Some(sha1) = v["stored_hashes"]["sha1"].as_str() {
        out.push_str(&format!("Stored SHA1: {sha1}\n"));
    }

    let meta = &v["metadata"];
    let fields = [
        ("Case number", "case_number"),
        ("Evidence #", "evidence_number"),
        ("Description", "description"),
        ("Examiner", "examiner"),
        ("Notes", "notes"),
        ("Software", "acquiry_software"),
        ("OS version", "os_version"),
        ("Acquired", "acquiry_date"),
        ("System date", "system_date"),
    ];
    let mut has_meta = false;
    for (label, key) in &fields {
        if let Some(val) = meta[key].as_str() {
            if !has_meta {
                out.push('\n');
                has_meta = true;
            }
            out.push_str(&format!("{label:12} {val}\n"));
        }
    }

    if let Some(errors) = v["acquisition_errors"].as_array() {
        if !errors.is_empty() {
            out.push_str(&format!("\nAcquisition errors: {}\n", errors.len()));
            for e in errors {
                out.push_str(&format!(
                    "  sector {} ({} sectors)\n",
                    e["first_sector"], e["sector_count"]
                ));
            }
        }
    }

    out
}

fn format_verify(v: &serde_json::Value) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "Computed MD5:  {}\n",
        v["computed_md5"].as_str().unwrap_or("n/a")
    ));
    if let Some(sha1) = v["computed_sha1"].as_str() {
        out.push_str(&format!("Computed SHA1: {sha1}\n"));
    }

    match v["md5_match"].as_bool() {
        Some(true) => out.push_str("MD5 match:     PASS\n"),
        Some(false) => out.push_str("MD5 match:     FAIL\n"),
        None => out.push_str("MD5 match:     n/a (no stored hash)\n"),
    }
    match v["sha1_match"].as_bool() {
        Some(true) => out.push_str("SHA1 match:    PASS\n"),
        Some(false) => out.push_str("SHA1 match:    FAIL\n"),
        None => out.push_str("SHA1 match:    n/a (no stored hash)\n"),
    }

    out
}

fn format_hex_dump(v: &serde_json::Value) -> String {
    let hex = v["hex"].as_str().unwrap_or("");
    let offset = v["offset"].as_u64().unwrap_or(0);
    let mut out = String::new();

    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();

    for (i, chunk) in bytes.chunks(16).enumerate() {
        let addr = offset + (i * 16) as u64;
        out.push_str(&format!("{addr:08x}  "));

        for (j, byte) in chunk.iter().enumerate() {
            out.push_str(&format!("{byte:02x} "));
            if j == 7 {
                out.push(' ');
            }
        }
        let pad = 16 - chunk.len();
        for j in 0..pad {
            out.push_str("   ");
            if chunk.len() + j == 7 {
                out.push(' ');
            }
        }

        out.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }

    out
}

fn format_sections(v: &serde_json::Value) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:<4} {:<12} {:>12} {:>12}\n",
        "Seg", "Type", "Offset", "Size"
    ));
    out.push_str(&format!("{}\n", "-".repeat(44)));

    if let Some(sections) = v["sections"].as_array() {
        for s in sections {
            out.push_str(&format!(
                "{:<4} {:<12} {:>12} {:>12}\n",
                s["segment"],
                s["type"].as_str().unwrap_or("?"),
                s["offset"],
                s["size"],
            ));
        }
    }
    out
}

fn format_search(v: &serde_json::Value) -> String {
    let mut out = String::new();
    let pattern = v["pattern"].as_str().unwrap_or("");
    let total = v["total_found"].as_u64().unwrap_or(0);

    out.push_str(&format!("Pattern: {pattern}\n"));
    out.push_str(&format!("Matches: {total}\n"));

    if let Some(matches) = v["matches"].as_array() {
        for m in matches {
            let offset = m["offset"].as_u64().unwrap_or(0);
            out.push_str(&format!("  0x{offset:08x} ({offset})\n"));
        }
    }
    out
}

fn format_extract(v: &serde_json::Value) -> String {
    format!(
        "Extracted {} bytes at offset {} to {}\n",
        v["bytes_written"],
        v["offset"],
        v["output"].as_str().unwrap_or("?")
    )
}

#[cfg(test)]
mod tests {
    use crate::handlers::*;

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
        assert_eq!(result["hex"].as_str().unwrap(), "55aa");
    }

    #[test]
    fn ewf_read_sectors_default_512_bytes() {
        let path = format!("{DATA_DIR}/exfat1.E01");
        let result = handle_ewf_read_sectors(&path, 0, 512).unwrap();
        let hex = result["hex"].as_str().unwrap();
        assert_eq!(hex.len(), 1024);
    }

    #[test]
    fn ewf_info_errors_on_bad_path() {
        let result = handle_ewf_info("/nonexistent/image.E01");
        assert!(result.is_err());
    }

    #[test]
    fn list_sections_returns_expected_types() {
        let path = format!("{DATA_DIR}/exfat1.E01");
        let result = handle_ewf_list_sections(&path).unwrap();
        let sections = result["sections"].as_array().unwrap();
        assert!(!sections.is_empty());
        let types: Vec<&str> = sections
            .iter()
            .map(|s| s["type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"volume"));
        assert!(types.contains(&"hash"));
        assert!(types.contains(&"done"));
    }

    #[test]
    fn list_sections_includes_offsets_and_sizes() {
        let path = format!("{DATA_DIR}/exfat1.E01");
        let result = handle_ewf_list_sections(&path).unwrap();
        let first = &result["sections"][0];
        assert!(first.get("offset").is_some());
        assert!(first.get("size").is_some());
        assert!(first.get("type").is_some());
    }

    #[test]
    fn search_finds_mbr_signature() {
        let path = format!("{DATA_DIR}/imageformat_mmls_1.E01");
        let result = handle_ewf_search(&path, "55aa", 100).unwrap();
        let matches = result["matches"].as_array().unwrap();
        assert!(!matches.is_empty());
        let offsets: Vec<u64> = matches
            .iter()
            .map(|m| m["offset"].as_u64().unwrap())
            .collect();
        assert!(offsets.contains(&510));
    }

    #[test]
    fn search_returns_empty_for_nonexistent_pattern() {
        let path = format!("{DATA_DIR}/nps-2010-emails.E01");
        let result = handle_ewf_search(&path, "deadbeefcafebabe", 10).unwrap();
        let matches = result["matches"].as_array().unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn search_respects_max_results() {
        let path = format!("{DATA_DIR}/exfat1.E01");
        let result = handle_ewf_search(&path, "00", 3).unwrap();
        let matches = result["matches"].as_array().unwrap();
        assert!(matches.len() <= 3);
    }

    #[test]
    fn extract_writes_correct_bytes() {
        let path = format!("{DATA_DIR}/imageformat_mmls_1.E01");
        let output = format!("{DATA_DIR}/../extract_test.bin");
        let result = handle_ewf_extract(&path, 510, 2, &output).unwrap();
        assert_eq!(result["bytes_written"], 2);
        let data = std::fs::read(&output).unwrap();
        assert_eq!(data, vec![0x55, 0xAA]);
        std::fs::remove_file(&output).unwrap();
    }

    #[test]
    fn extract_clamps_to_media_size() {
        let path = format!("{DATA_DIR}/nps-2010-emails.E01");
        let output = format!("{DATA_DIR}/../extract_clamp_test.bin");
        let result = handle_ewf_extract(&path, 10_485_750, 100, &output).unwrap();
        assert_eq!(result["bytes_written"], 10);
        std::fs::remove_file(&output).unwrap();
    }

    #[test]
    fn search_rejects_odd_length_hex() {
        let path = format!("{DATA_DIR}/nps-2010-emails.E01");
        let result = handle_ewf_search(&path, "ABC", 10);
        assert!(result.is_err());
    }

    #[test]
    fn search_rejects_empty_hex() {
        let path = format!("{DATA_DIR}/nps-2010-emails.E01");
        let result = handle_ewf_search(&path, "", 10);
        assert!(result.is_err());
    }
}
