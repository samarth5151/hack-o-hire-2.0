# Attachment Scanner — Main Entry Point
# Fully rule-based malicious attachment detection (ML removed)

from magic_detector import detect
from pdf_analyzer import analyze as analyze_pdf
from office_analyzer import analyze as analyze_office
from pe_analyzer import analyze as analyze_pe
from zip_analyzer import analyze as analyze_zip
from pattern_engine import scan as scan_patterns
from hash_checker import check as check_hash


def calculate_final_risk(
    all_findings,
    file_type,
    hash_result,
    filename
):

    from magic_detector import (
        HIGH_RISK_EXTENSIONS,
        MEDIUM_RISK_EXTENSIONS
    )

    ext = file_type.get("declared_extension", "")
    score = 0

    # Known malware hash match
    if hash_result.get("known_malware"):
        score += 100

    # High-risk extensions (.exe, .dll, etc.)
    if ext in HIGH_RISK_EXTENSIONS:
        score += 50

    # Medium-risk extensions (.docm, .pdf, .zip, etc.)
    if ext in MEDIUM_RISK_EXTENSIONS:
        score += 20

    # Extension mismatch detection
    if file_type.get("extension_mismatch"):
        score += 40

    # Rule severity weights
    tier_points = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3
    }

    for finding in all_findings:
        score += tier_points.get(
            finding.get("risk_tier", "Low"), 3
        )

    # Cap score at 100
    score = min(score, 100)

    # Assign final label
    if score >= 80:
        label = "Critical"
    elif score >= 60:
        label = "High"
    elif score >= 40:
        label = "Medium"
    elif score > 0:
        label = "Low"
    else:
        label = "Clean"

    return {"score": score, "label": label}


def analyze_attachment(file_bytes, filename):

    ext = (
        "." + filename.lower().rsplit(".", 1)[-1]
        if "." in filename else ""
    )

    # Stage 1 — file type detection
    file_type = detect(file_bytes, filename)

    # Stage 2 — analyzers
    all_findings = []

    # Extension mismatch rule
    if file_type.get("extension_mismatch"):

        all_findings.append({
            "stage": "File Type Detection",
            "rule": "extension_mismatch",
            "description":
                file_type["mismatch_desc"],
            "risk_tier": "Critical",
            "category": "evasion",
        })

    # PDF analyzer
    if (
        ext == ".pdf"
        or file_bytes[:4] == b"\x25\x50\x44\x46"
    ):
        all_findings += analyze_pdf(file_bytes)

    # Office analyzer
    if ext in (
        ".doc", ".xls", ".ppt",
        ".docx", ".xlsx", ".pptx",
        ".docm", ".xlsm", ".pptm"
    ):
        all_findings += analyze_office(
            file_bytes,
            filename
        )

    # PE analyzer
    if file_bytes[:2] == b"\x4d\x5a":
        all_findings += analyze_pe(file_bytes)

    # ZIP analyzer
    if file_bytes[:4] == b"\x50\x4b\x03\x04":
        all_findings += analyze_zip(file_bytes)

    # Pattern engine (YARA-style rules)
    all_findings += scan_patterns(file_bytes)

    # Stage 3 — hash lookup
    hash_result = check_hash(file_bytes)

    # Final rule-based risk score
    risk = calculate_final_risk(
        all_findings,
        file_type,
        hash_result,
        filename
    )

    # Generate human-readable summary
    human_summary = _build_summary(
        all_findings, file_type, hash_result, risk
    )
    recommended_action = _build_action(risk["label"])

    # Helper function to count severity tiers
    def count(tier):
        return sum(
            1 for f in all_findings
            if f.get("risk_tier") == tier
        )

    return {

        "module":
            "Malicious Attachment Analyzer",

        "filename":
            filename,

        "file_size_kb":
            file_type["file_size_kb"],

        "all_findings":
            all_findings,

        "stages": {

            "stage_1_file_type":
                file_type,

            "stage_2_findings":
                all_findings,

            "stage_3_hash":
                hash_result,

            "stage_4_ml":
                "Disabled (rule-based scoring only)",
        },

        "total_findings":
            len(all_findings),

        "critical_count":
            count("Critical"),

        "high_count":
            count("High"),

        "medium_count":
            count("Medium"),

        "low_count":
            count("Low"),

        "risk_score":
            risk["score"],

        "risk_label":
            risk["label"],

        "human_summary":
            human_summary,

        "recommended_action":
            recommended_action,
    }


def _build_summary(findings, file_type, hash_result, risk):
    """Generate a human-readable summary of the scan."""
    parts = []

    if not findings and not hash_result.get("known_malware"):
        return "No suspicious indicators detected. File appears safe."

    if hash_result.get("known_malware"):
        parts.append(
            f"Hash matches known malware: {hash_result['known_malware']}."
        )

    if file_type.get("extension_mismatch"):
        parts.append("File extension does not match actual content.")

    # Summarise by stage
    stages_seen = {}
    for f in findings:
        stage = f.get("stage", "Unknown")
        stages_seen[stage] = stages_seen.get(stage, 0) + 1

    if stages_seen:
        stage_parts = [
            f"{count} finding(s) from {stage}"
            for stage, count in stages_seen.items()
        ]
        parts.append(
            f"Found {len(findings)} indicator(s): "
            + ", ".join(stage_parts) + "."
        )

    # Severity breakdown
    crit = sum(1 for f in findings if f.get("risk_tier") == "Critical")
    high = sum(1 for f in findings if f.get("risk_tier") == "High")
    if crit:
        parts.append(f"{crit} critical-severity indicator(s).")
    if high:
        parts.append(f"{high} high-severity indicator(s).")

    return " ".join(parts) if parts else "Scan complete."


def _build_action(label):
    """Return recommended action based on risk label."""
    actions = {
        "Clean":    "No action required. File is safe.",
        "Low":      "Low risk — review if file origin is untrusted.",
        "Medium":   "Quarantine file and review with security team.",
        "High":     "Block file. Investigate source and alert SOC.",
        "Critical": "IMMEDIATE: Block, quarantine, escalate to SOC, notify compliance.",
    }
    return actions.get(label, "Review manually.")