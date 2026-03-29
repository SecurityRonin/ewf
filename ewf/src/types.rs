/// Integrity hashes stored within the EWF image by the acquisition tool.
///
/// The `hash` section (present since EnCase 1) stores an MD5 of the acquired media.
/// The `digest` section (added in EnCase 6.12+) stores both MD5 and SHA-1.
/// When both sections are present, MD5 values should be identical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHashes {
    /// MD5 hash of the acquired media (from `hash` or `digest` section).
    pub md5: Option<[u8; 16]>,
    /// SHA-1 hash of the acquired media (from `digest` section only).
    pub sha1: Option<[u8; 20]>,
}

/// Result of verifying the EWF image integrity by recomputing media hashes.
#[cfg(feature = "verify")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    /// Computed MD5 of the full media stream.
    pub computed_md5: [u8; 16],
    /// Computed SHA-1 of the full media stream (only computed if a stored SHA-1 exists).
    pub computed_sha1: Option<[u8; 20]>,
    /// `Some(true)` if computed MD5 matches stored MD5, `Some(false)` if mismatch,
    /// `None` if no stored MD5 was present.
    pub md5_match: Option<bool>,
    /// `Some(true)` if computed SHA-1 matches stored SHA-1, `Some(false)` if mismatch,
    /// `None` if no stored SHA-1 was present.
    pub sha1_match: Option<bool>,
}

/// Case and acquisition metadata extracted from EWF header sections.
///
/// Populated from the `header` section (ASCII, always present) or `header2` section
/// (UTF-16LE, EnCase 5+). Fields are `None` when the acquisition tool left them blank.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EwfMetadata {
    pub case_number: Option<String>,
    pub evidence_number: Option<String>,
    pub description: Option<String>,
    pub examiner: Option<String>,
    pub notes: Option<String>,
    pub acquiry_software: Option<String>,
    pub os_version: Option<String>,
    pub acquiry_date: Option<String>,
    pub system_date: Option<String>,
}

/// A range of sectors that had read errors during acquisition.
///
/// Extracted from the `error2` section, which records bad sectors encountered
/// by the imaging tool. Clean acquisitions have no entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquisitionError {
    /// First sector in the error range.
    pub first_sector: u32,
    /// Number of consecutive sectors in the error range.
    pub sector_count: u32,
}
