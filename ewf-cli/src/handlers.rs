use serde_json::{json, Value};

pub fn hex_string(bytes: &[u8]) -> String {
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
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|e| format!("{e}"))?;
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

    let first = Path::new(path);
    let stem = first
        .file_stem()
        .and_then(|s| s.to_str())
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
            seg_paths.extend(entries.filter_map(std::result::Result::ok));
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
        let mut offset: u64 = 13;

        loop {
            if offset + 76 > file_len {
                break;
            }
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| format!("{e}"))?;
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

pub fn handle_ewf_search(
    path: &str,
    pattern_hex: &str,
    max_results: usize,
) -> Result<Value, String> {
    use std::io::{Read, Seek, SeekFrom};

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
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| format!("{e}"))?;

    let mut matches = Vec::new();
    let buf_size = 64 * 1024;
    let mut buf = vec![0u8; buf_size + pattern.len() - 1];
    let mut file_offset: u64 = 0;
    let mut carry = 0usize;

    while file_offset < total && matches.len() < max_results {
        let to_read = buf_size.min((total - file_offset) as usize);
        let n = reader
            .read(&mut buf[carry..carry + to_read])
            .map_err(|e| format!("{e}"))?;
        if n == 0 {
            break;
        }
        let search_len = carry + n;

        let end = if search_len >= pattern.len() {
            search_len - pattern.len() + 1
        } else {
            0
        };
        for i in 0..end {
            if buf[i..i + pattern.len()] == pattern[..] {
                let match_offset = file_offset - carry as u64 + i as u64;
                matches.push(json!({ "offset": match_offset }));
                if matches.len() >= max_results {
                    break;
                }
            }
        }

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

pub fn handle_ewf_extract(
    path: &str,
    offset: u64,
    length: u64,
    output: &str,
) -> Result<Value, String> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut reader = ewf::EwfReader::open(path).map_err(|e| format!("{e}"))?;
    let total = reader.total_size();
    if offset >= total {
        return Err(format!("offset {offset} exceeds media size {total}"));
    }
    let actual_len = length.min(total - offset);
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|e| format!("{e}"))?;

    let mut outfile = std::fs::File::create(output).map_err(|e| format!("{e}"))?;
    let mut remaining = actual_len;
    let mut buf = vec![0u8; 64 * 1024];

    while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len());
        let n = reader
            .read(&mut buf[..to_read])
            .map_err(|e| format!("{e}"))?;
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
