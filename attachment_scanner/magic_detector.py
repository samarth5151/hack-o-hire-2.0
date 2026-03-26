# magic_detector.py
# Stage 1 — File Type Detection
# Uses python-magic library which contains 500+ file signatures
# Works completely offline — no internet required

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("WARNING: python-magic-bin not installed")
    print("Run: pip install python-magic-bin")


# Fallback signatures if python-magic not available
FALLBACK_SIGNATURES = {
    b"\x4d\x5a":          "PE Executable (.exe/.dll)",
    b"\x50\x4b\x03\x04":  "ZIP/Office Archive",
    b"\x25\x50\x44\x46":  "PDF Document",
    b"\xd0\xcf\x11\xe0":  "MS Office Legacy (.doc/.xls)",
    b"\x7f\x45\x4c\x46":  "Linux ELF Executable",
    b"\xca\xfe\xba\xbe":  "Java Class File",
    b"\x52\x61\x72\x21":  "RAR Archive",
    b"\x1f\x8b":           "GZIP Compressed",
    b"\x37\x7a\xbc\xaf":  "7-ZIP Archive",
    b"\x89\x50\x4e\x47":  "PNG Image",
    b"\xff\xd8\xff":       "JPEG Image",
    b"\x47\x49\x46\x38":  "GIF Image",
    b"\x42\x4d":           "BMP Image",
    b"\x23\x21":           "Script file (shebang)",
}

HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1",
    ".vbs", ".js",  ".jar", ".sh",  ".msi",
    ".scr", ".pif", ".com", ".hta", ".wsf",
    ".reg", ".py",  ".rb",  ".pl",  ".sys",
    ".drv", ".ocx", ".cpl", ".msc", ".inf",
    ".lnk", ".url", ".jse", ".vbe", ".wsh",
}

MEDIUM_RISK_EXTENSIONS = {
    ".zip",  ".rar", ".7z",  ".gz",   ".tar",
    ".doc",  ".xls", ".ppt", ".docm", ".xlsm",
    ".pptm", ".iso", ".img", ".cab",  ".msp",
}

# MIME types that indicate high risk
HIGH_RISK_MIMES = {
    "application/x-dosexec",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-msi",
    "application/x-sh",
    "application/x-shellscript",
    "application/x-msdos-program",
    "application/x-msdownload",
    "application/java-archive",
    "application/x-java-applet",
}

MEDIUM_RISK_MIMES = {
    "application/zip",
    "application/x-rar-compressed",
    "application/x-7z-compressed",
    "application/vnd.ms-office",
    "application/msword",
    "application/x-ms-installer",
    "application/x-iso9660-image",
}


def detect_with_magic(file_bytes: bytes) -> tuple:
    """
    Use python-magic to detect file type from bytes.
    Returns (mime_type, description)
    """
    try:
        mime_type   = magic.from_buffer(file_bytes, mime=True)
        description = magic.from_buffer(file_bytes)
        return mime_type, description
    except Exception as e:
        print(f"python-magic error: {e}")
        return "unknown", "Unknown"


def detect_with_fallback(file_bytes: bytes) -> tuple:
    """
    Fallback detection using hardcoded magic bytes.
    Used when python-magic is not available.
    """
    for magic_bytes, description in FALLBACK_SIGNATURES.items():
        if file_bytes[:len(magic_bytes)] == magic_bytes:
            return "unknown", description
    return "unknown", "Unknown"


def check_mismatch(ext: str, mime_type: str,
                   detected_type: str,
                   file_bytes: bytes) -> tuple:
    """
    Check if declared extension matches detected file type.
    Returns (mismatch: bool, description: str)
    """
    mismatch = False
    desc     = ""

    # PDF mismatch
    if ext == ".pdf" and "pdf" not in mime_type.lower() \
       and file_bytes[:4] != b"\x25\x50\x44\x46":
        mismatch = True
        desc     = (f"Claims to be PDF but detected as "
                    f"{detected_type}")

    # Office mismatch
    elif ext in (".docx", ".xlsx", ".pptx") \
         and "zip" not in mime_type.lower() \
         and "office" not in mime_type.lower() \
         and file_bytes[:2] != b"\x50\x4b":
        mismatch = True
        desc     = (f"Claims to be Office doc but detected as "
                    f"{detected_type}")

    # JPEG mismatch
    elif ext in (".jpg", ".jpeg") \
         and "jpeg" not in mime_type.lower() \
         and file_bytes[:3] != b"\xff\xd8\xff":
        mismatch = True
        desc     = (f"Claims to be JPEG but detected as "
                    f"{detected_type}")

    # PNG mismatch
    elif ext == ".png" \
         and "png" not in mime_type.lower() \
         and file_bytes[:4] != b"\x89\x50\x4e\x47":
        mismatch = True
        desc     = (f"Claims to be PNG but detected as "
                    f"{detected_type}")

    # Executable disguised as something else
    elif ext not in (".exe", ".dll", ".sys", ".drv") \
         and (mime_type in HIGH_RISK_MIMES
              or file_bytes[:2] == b"\x4d\x5a"):
        mismatch = True
        desc     = (f"Windows executable disguised as {ext}")

    # Plain text disguised as binary
    elif ext in (".pdf", ".docx", ".xlsx", ".exe",
                 ".dll", ".zip") \
         and mime_type in ("text/plain", "unknown") \
         and detected_type == "Unknown":
        try:
            file_bytes[:500].decode("utf-8")
            mismatch = True
            desc     = (f"Claims to be {ext} but content is "
                        f"plain text — possible evasion")
        except UnicodeDecodeError:
            pass

    # Double extension check e.g. invoice.pdf.exe
    filename_parts = ext.split(".")
    if len(filename_parts) > 2:
        real_ext = "." + filename_parts[-1]
        if real_ext in HIGH_RISK_EXTENSIONS:
            mismatch = True
            desc     = (f"Double extension detected — "
                        f"hiding {real_ext}")

    return mismatch, desc


def detect(file_bytes: bytes, filename: str) -> dict:
    """
    Main detection function.
    Uses python-magic if available, falls back to
    hardcoded signatures if not.
    """
    ext = ("." + filename.lower().rsplit(".", 1)[-1]
           if "." in filename else "")

    # Detect file type
    if MAGIC_AVAILABLE:
        mime_type, detected_type = detect_with_magic(file_bytes)
        method = "python-magic (500+ signatures)"
    else:
        mime_type, detected_type = detect_with_fallback(file_bytes)
        method = "fallback signatures (28 signatures)"

    # Check for mismatch
    mismatch, mismatch_desc = check_mismatch(
        ext, mime_type, detected_type, file_bytes
    )

    # Determine risk level
    if mismatch:
        risk = "Critical"
    elif mime_type in HIGH_RISK_MIMES:
        risk = "High"
    elif ext in HIGH_RISK_EXTENSIONS:
        risk = "High"
    elif mime_type in MEDIUM_RISK_MIMES:
        risk = "Medium"
    elif ext in MEDIUM_RISK_EXTENSIONS:
        risk = "Medium"
    else:
        risk = "Info"

    return {
        "declared_extension": ext,
        "detected_type":      detected_type,
        "mime_type":          mime_type,
        "extension_mismatch": mismatch,
        "mismatch_desc":      mismatch_desc,
        "file_size_kb":       round(len(file_bytes) / 1024, 2),
        "risk_level":         risk,
        "detection_method":   method,
    }