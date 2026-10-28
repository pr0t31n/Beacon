"""Beacon webhook parsers — normalize third-party tool payloads to internal model."""
from __future__ import annotations


def _empty_result(source):
    return {
        "source": source,
        "source_version": "",
        "task_id": "",
        "task_name": "",
        "status": "unknown",
        "progress": None,
        "started_at": None,
        "ended_at": None,
        "message": "",
        "findings_summary": None,
        "metadata": {},
    }


def _clamp_progress(v):
    if v is None:
        return None
    try:
        f = float(v)
        return max(0.0, min(1.0, f))
    except (TypeError, ValueError):
        return None


def _severity_counts(data, key_map):
    out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for src_key, dst_key in key_map.items():
        v = data.get(src_key, 0)
        try:
            out[dst_key] += int(v)
        except (TypeError, ValueError):
            pass
    if not any(out.values()):
        return None
    return out


def _str(v, default=""):
    if v is None:
        return default
    return str(v)


# ── Generic ──────────────────────────────────────────────────────────────

_GENERIC_STATUSES = {"queued", "running", "paused", "complete", "failed", "cancelled"}


def parse_generic(data):
    r = _empty_result("generic")
    r["source"] = _str(data.get("source"), "generic")
    r["source_version"] = _str(data.get("source_version"))
    r["task_id"] = _str(data.get("task_id"))
    if not r["task_id"]:
        return None
    r["task_name"] = _str(data.get("task_name"))
    st = _str(data.get("status")).lower()
    r["status"] = st if st in _GENERIC_STATUSES else "unknown"
    r["progress"] = _clamp_progress(data.get("progress"))
    r["started_at"] = data.get("started_at")
    r["ended_at"] = data.get("ended_at")
    r["message"] = _str(data.get("message"))
    fs = data.get("findings_summary")
    if isinstance(fs, dict):
        norm = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for k, v in fs.items():
            ku = k.upper()
            if ku in norm:
                try:
                    norm[ku] += int(v)
                except (TypeError, ValueError):
                    pass
        r["findings_summary"] = norm if any(norm.values()) else None
    md = data.get("metadata")
    r["metadata"] = md if isinstance(md, dict) else {}
    return r


# ── GoPhish ──────────────────────────────────────────────────────────────

_GOPHISH_STATUS = {
    "in progress": "running", "completed": "complete",
    "queued": "queued", "created": "queued",
}


def parse_gophish(data):
    r = _empty_result("gophish")
    r["task_id"] = _str(data.get("campaign_id") or data.get("id"))
    if not r["task_id"]:
        return None
    r["task_name"] = _str(data.get("campaign_name") or data.get("name", ""))
    raw_st = _str(data.get("status")).lower()
    r["status"] = _GOPHISH_STATUS.get(raw_st, "unknown")
    r["started_at"] = data.get("launch_date") or data.get("created_date")
    r["ended_at"] = data.get("completed_date") or data.get("send_by_date")
    stats = data.get("stats") or data.get("results_summary") or {}
    parts = []
    for k in ("email_sent", "email_opened", "clicked_link", "submitted_data", "email_reported"):
        v = stats.get(k)
        if v is not None:
            parts.append(f"{k.replace('_', ' ')}: {v}")
    r["message"] = ", ".join(parts) if parts else _str(data.get("status"))
    r["findings_summary"] = None
    r["metadata"] = {
        "stats": stats,
        **{k: data[k] for k in ("template", "page", "smtp", "url") if k in data},
    }
    return r


# ── Semgrep Cloud ────────────────────────────────────────────────────────

_SEMGREP_STATUS = {
    "completed": "complete", "running": "running", "queued": "queued",
    "failed": "failed", "started": "running",
}


def parse_semgrep(data):
    r = _empty_result("semgrep")
    scan = data.get("scan") or data
    r["task_id"] = _str(scan.get("id") or data.get("deployment_id"))
    if not r["task_id"]:
        return None
    r["task_name"] = _str(data.get("deployment_name") or data.get("repository", ""))
    raw_st = _str(scan.get("status", data.get("status", ""))).lower()
    r["status"] = _SEMGREP_STATUS.get(raw_st, "unknown")
    r["started_at"] = scan.get("started_at") or data.get("started_at")
    r["ended_at"] = scan.get("completed_at") or data.get("completed_at")
    r["message"] = _str(scan.get("status", data.get("status", "")))

    fc = data.get("findings_count") or scan.get("findings_count")
    if isinstance(fc, dict):
        r["findings_summary"] = _severity_counts(fc, {
            "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
            "low": "LOW", "info": "INFO", "warning": "MEDIUM",
        })
    elif isinstance(fc, int):
        r["findings_summary"] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": fc, "LOW": 0, "INFO": 0}

    r["metadata"] = {k: data[k] for k in ("deployment_id", "deployment_slug", "repository", "branch", "commit") if k in data}
    return r


# ── SonarQube ────────────────────────────────────────────────────────────

_SQ_STATUS = {
    "success": "complete", "error": "failed", "pending": "queued",
    "in_progress": "running", "canceled": "cancelled",
    "cancelled": "cancelled",
}


def parse_sonarqube(data):
    r = _empty_result("sonarqube")
    r["task_id"] = _str(data.get("taskId"))
    if not r["task_id"]:
        return None
    project = data.get("project") or {}
    r["task_name"] = _str(project.get("name") or project.get("key", ""))
    raw_st = _str(data.get("status")).lower()
    r["status"] = _SQ_STATUS.get(raw_st, "unknown")
    r["started_at"] = data.get("analysedAt") or data.get("submittedAt")
    r["ended_at"] = data.get("analysedAt") if r["status"] == "complete" else None
    qg = data.get("qualityGate") or {}
    qg_status = qg.get("status", "")
    r["message"] = f"Quality gate: {qg_status}" if qg_status else _str(data.get("status"))

    conditions = qg.get("conditions") or []
    r["findings_summary"] = None
    r["metadata"] = {
        "project_key": _str(project.get("key")),
        "quality_gate_status": _str(qg_status),
        "quality_gate_conditions": conditions,
        "branch": _str(data.get("branch", {}).get("name") if isinstance(data.get("branch"), dict) else data.get("branch")),
        "server_url": _str(data.get("serverUrl")),
    }
    return r


# ── Snyk ─────────────────────────────────────────────────────────────────

def parse_snyk(data):
    r = _empty_result("snyk")
    project = data.get("project") or {}
    r["task_id"] = _str(project.get("id") or data.get("id"))
    if not r["task_id"]:
        return None
    r["task_name"] = _str(project.get("name") or data.get("projectName", ""))

    new_issues = data.get("newIssues") or []
    removed = data.get("removedIssues") or []
    r["status"] = "complete"
    r["ended_at"] = data.get("testDate") or data.get("created")
    r["message"] = f"+{len(new_issues)} new, -{len(removed)} removed"

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for issue in new_issues:
        sev = _str(issue.get("issueData", {}).get("severity",
                   issue.get("severity", ""))).upper()
        if sev in counts:
            counts[sev] += 1
    for issue in (data.get("existingIssues") or []):
        sev = _str(issue.get("issueData", {}).get("severity",
                   issue.get("severity", ""))).upper()
        if sev in counts:
            counts[sev] += 1
    r["findings_summary"] = counts if any(counts.values()) else None
    r["metadata"] = {
        "org_id": _str(data.get("org", {}).get("id")),
        "group_id": _str(data.get("group", {}).get("id")),
        "new_issues_count": len(new_issues),
        "removed_issues_count": len(removed),
    }
    return r


# ── Checkmarx One ────────────────────────────────────────────────────────

_CX_STATUS = {
    "completed": "complete", "running": "running", "failed": "failed",
    "queued": "queued", "canceled": "cancelled", "new": "queued",
    "prestage": "queued", "scanning": "running",
}


def parse_checkmarx(data):
    r = _empty_result("checkmarx")
    r["task_id"] = _str(data.get("id") or data.get("scanId"))
    if not r["task_id"]:
        return None
    r["task_name"] = _str(data.get("projectName") or data.get("project", {}).get("name", ""))
    raw_st = _str(data.get("status")).lower()
    r["status"] = _CX_STATUS.get(raw_st, "unknown")
    r["started_at"] = data.get("dateCreated") or data.get("createdDate")
    r["ended_at"] = data.get("dateFinished") or data.get("finishedDate")
    r["message"] = _str(data.get("status"))
    rs = data.get("resultsStatistics") or data.get("scanResults") or {}
    if isinstance(rs, dict):
        r["findings_summary"] = _severity_counts(rs, {
            "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW", "Info": "INFO",
            "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO",
            "highSeverity": "HIGH", "mediumSeverity": "MEDIUM",
            "lowSeverity": "LOW", "infoSeverity": "INFO",
        })
    r["source_version"] = _str(data.get("engineVersion"))
    r["metadata"] = {k: data[k] for k in ("projectId", "origin", "scanType", "isIncremental") if k in data}
    return r


# ── Registry ─────────────────────────────────────────────────────────────

PARSERS = {
    "generic": parse_generic,
    "checkmarx": parse_checkmarx,
    "gophish": parse_gophish,
    "semgrep": parse_semgrep,
    "sonarqube": parse_sonarqube,
    "snyk": parse_snyk,
}

PROVIDER_NAMES = {
    "generic": "Generic",
    "checkmarx": "Checkmarx One",
    "gophish": "GoPhish",
    "semgrep": "Semgrep Cloud",
    "sonarqube": "SonarQube",
    "snyk": "Snyk",
}


def parse(provider, data):
    fn = PARSERS.get(provider)
    if fn is None:
        return None
    try:
        return fn(data)
    except Exception:
        return None
