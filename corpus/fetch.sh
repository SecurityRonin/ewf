#!/usr/bin/env bash
# Fetch DFTT (Digital Forensics Tool Testing) EWF corpus images.
# Source: https://dftt.sourceforge.net — public domain reference images.
# These are produced by EnCase / ewfacquire, not by our parser.
set -euo pipefail

DEST="$(cd "$(dirname "$0")" && pwd)"

# DFTT image 10 — small EWF/E01 with a FAT12 filesystem (public domain)
curl -fLo "${DEST}/test_data_10.tar.gz" \
  "https://dftt.sourceforge.net/test10/index.html" 2>/dev/null || \
curl -fLo "${DEST}/test_data_10.tar.gz" \
  "https://archive.org/download/dftt/dftt10.tar.gz" 2>/dev/null || true

# If download fails, create a placeholder so the CI corpus job doesn't error.
# The corpus tests skip gracefully when the expected files are absent.
if [ ! -f "${DEST}/test_data_10.tar.gz" ] || [ ! -s "${DEST}/test_data_10.tar.gz" ]; then
  echo "WARNING: could not download DFTT corpus; creating empty placeholder" >&2
  touch "${DEST}/.no_corpus"
fi
