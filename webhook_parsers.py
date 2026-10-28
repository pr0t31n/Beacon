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


# ── Nessus ───────────────────────────────────────────────────────────────

_NESSUS_STATUS = {
    "completed": "complete", "running": "running", "paused": "paused",
    "canceled": "cancelled", "aborted": "failed", "pending": "queued",
    "imported": "complete", "stopping": "cancelled",
}


def parse_nessus(data):
    r = _empty_result("nessus")
    r["task_id"] = _str(data.get("scan_id"))
    if not r["task_id"]:
        return None
    r["task_name"] = _str(data.get("scan_name", data.get("name", "")))
    raw_st = _str(data.get("status")).lower()
    r["status"] = _NESSUS_STATUS.get(raw_st, "unknown")
    r["started_at"] = data.get("start_time") or data.get("scan_start")
    r["ended_at"] = data.get("end_time") or data.get("scan_end")
    r["message"] = _str(data.get("status"))
    sc = data.get("severity_counts") or data.get("host_vulns_summary") or {}
    if isinstance(sc, dict):
        r["findings_summary"] = _severity_counts(sc, {
            "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
            "low": "LOW", "info": "INFO", "informational": "INFO",
            "4": "CRITICAL", "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO",
        })
    r["source_version"] = _str(data.get("scanner_version"))
    r["metadata"] = {k: data[k] for k in ("scan_type", "policy", "targets", "folder_id") if k in data}
    return r


# ── Qualys ───────────────────────────────────────────────────────────────

_QUALYS_STATUS = {
    "finished": "complete", "running": "running", "queued": "queued",
    "paused": "paused", "canceled": "cancelled", "error": "failed",
    "loading": "running", "submitted": "queued",
}


def parse_qualys(data):
    r = _empty_result("qualys")
    r["task_id"] = _str(data.get("id") or data.get("scanId"))
    if not r["task_id"]:
        return None
    r["task_name"] = _str(data.get("title") or data.get("scanName", ""))
    raw_st = _str(data.get("status")).lower()
    r["status"] = _QUALYS_STATUS.get(raw_st, "unknown")
    r["started_at"] = data.get("launchDate") or data.get("launchDatetime")
    r["ended_at"] = data.get("endDate") or data.get("endDatetime")
    r["message"] = _str(data.get("statusMessage", data.get("status", "")))
    sc = data.get("severity_counts") or {}
    if isinstance(sc, dict):
        r["findings_summary"] = _severity_counts(sc, {
            "5": "CRITICAL", "4": "HIGH", "3": "MEDIUM", "2": "LOW", "1": "INFO",
            "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
            "low": "LOW", "info": "INFO",
        })
    r["metadata"] = {k: data[k] for k in ("type", "target", "option", "scannerName") if k in data}
    return r


# ── InsightVM (Rapid7) ───────────────────────────────────────────────────

_IVM_STATUS = {
    "started": "running", "running": "running", "finished": "complete",
    "completed": "complete", "stopped": "cancelled", "failed": "failed",
    "paused": "paused", "queued": "queued",
    "integrating": "running", "dispatched": "running",
}


def parse_insightvm(data):
    r = _empty_result("insightvm")
    scan = data.get("scan") or data
    r["task_id"] = _str(scan.get("id") or scan.get("scanId"))
    if not r["task_id"]:
        return None
    r["task_name"] = _str(scan.get("scanName") or scan.get("name", ""))
    raw_st = _str(scan.get("status")).lower()
    r["status"] = _IVM_STATUS.get(raw_st, "unknown")
    r["started_at"] = scan.get("startTime") or scan.get("start_time")
    r["ended_at"] = scan.get("endTime") or scan.get("end_time")
    r["message"] = _str(data.get("event", scan.get("status", "")))
    vulns = scan.get("vulnerabilities") or {}
    if isinstance(vulns, dict):
        r["findings_summary"] = _severity_counts(vulns, {
            "critical": "CRITICAL", "severe": "HIGH", "moderate": "MEDIUM",
            "low": "LOW", "informational": "INFO",
        })
    r["source_version"] = _str(scan.get("engineVersion"))
    r["metadata"] = {k: scan[k] for k in ("siteId", "siteName", "engineId", "assets") if k in scan}
    return r


# ── OpenVAS / Greenbone ──────────────────────────────────────────────────

_OPENVAS_STATUS = {
    "done": "complete", "running": "running", "requested": "queued",
    "queued": "queued", "stop requested": "cancelled", "stopped": "cancelled",
    "interrupted": "failed", "new": "queued",
}


def parse_openvas(data):
    r = _empty_result("openvas")
    r["task_id"] = _str(data.get("task_id"))
    if not r["task_id"]:
        return None
    r["task_name"] = _str(data.get("task_name", ""))
    raw_st = _str(data.get("status")).lower()
    r["status"] = _OPENVAS_STATUS.get(raw_st, "unknown")
    pct = data.get("progress")
    r["progress"] = _clamp_progress(int(pct) / 100.0 if pct is not None else None)
    r["started_at"] = data.get("start_time")
    r["ended_at"] = data.get("end_time")
    r["message"] = _str(data.get("status"))
    report = data.get("report") or {}
    sc = report.get("severity_counts") or {}
    if isinstance(sc, dict):
        r["findings_summary"] = _severity_counts(sc, {
            "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "log": "INFO",
            "alarm": "CRITICAL", "critical": "CRITICAL",
        })
    r["metadata"] = {k: data[k] for k in ("report_id", "scan_config", "target") if k in data}
    return r


# ── Burp Suite Enterprise ────────────────────────────────────────────────

_BURP_STATUS = {
    "queued": "queued", "running": "running", "succeeded": "complete",
    "failed": "failed", "cancelled": "cancelled", "paused": "paused",
    "scheduled": "queued",
}


def parse_burp_enterprise(data):
    r = _empty_result("burp_enterprise")
    r["task_id"] = _str(data.get("scan_id"))
    if not r["task_id"]:
        return None
    r["task_name"] = _str(data.get("scan_name", ""))
    raw_st = _str(data.get("scan_status")).lower()
    r["status"] = _BURP_STATUS.get(raw_st, "unknown")
    r["started_at"] = data.get("start_time")
    r["ended_at"] = data.get("end_time")
    pct = data.get("scan_metrics", {}).get("crawl_and_audit_progress")
    r["progress"] = _clamp_progress(int(pct) / 100.0 if pct is not None else None)
    r["message"] = _str(data.get("scan_status"))
    ic = data.get("issue_counts") or {}
    if isinstance(ic, dict):
        r["findings_summary"] = _severity_counts(ic, {
            "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
            "low": "LOW", "info": "INFO", "information": "INFO",
        })
    r["source_version"] = _str(data.get("scanner_version"))
    r["metadata"] = {k: data[k] for k in ("site_id", "site_name", "scan_configuration_id", "agent_id") if k in data}
    return r


# ── Checkmarx ────────────────────────────────────────────────────────────

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


# ── Trivy ────────────────────────────────────────────────────────────────

def parse_trivy(data):
    r = _empty_result("trivy")
    target = data.get("ArtifactName") or data.get("target") or data.get("Target") or ""
    r["task_id"] = _str(target) or _str(data.get("id"))
    if not r["task_id"]:
        return None
    r["task_name"] = _str(target)
    # Trivy webhooks are typically post-scan results, so status = complete
    raw_st = _str(data.get("status", "complete")).lower()
    r["status"] = "complete" if raw_st in ("", "complete", "success") else raw_st
    r["started_at"] = data.get("CreatedAt") or data.get("started_at")
    r["ended_at"] = data.get("completed_at") or data.get("ended_at")
    r["message"] = f"Scan of {target}" if target else ""

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    results = data.get("Results") or []
    if not results:
        vulns = data.get("vulnerabilities") or data.get("Vulnerabilities") or []
        results = [{"Vulnerabilities": vulns}] if vulns else []
    for result in results:
        for v in (result.get("Vulnerabilities") or []):
            sev = _str(v.get("Severity", "")).upper()
            if sev == "UNKNOWN":
                sev = "INFO"
            if sev in counts:
                counts[sev] += 1
    r["findings_summary"] = counts if any(counts.values()) else None
    r["source_version"] = _str(data.get("SchemaVersion") or data.get("scanner_version"))
    r["metadata"] = {"artifact_type": _str(data.get("ArtifactType")),
                     "os_family": _str(data.get("Metadata", {}).get("OS", {}).get("Family"))}
    return r


# ── Veracode ─────────────────────────────────────────────────────────────

_VERACODE_STATUS = {
    "results ready": "complete", "scan in progress": "running",
    "pre-scan success": "running", "incomplete": "failed",
    "not submitted to engine": "queued", "submitted to engine": "running",
    "scan errors": "failed", "pre-scan submitted": "queued",
    "pre-scan failed": "failed",
}


def parse_veracode(data):
    r = _empty_result("veracode")
    r["task_id"] = _str(data.get("build_id") or data.get("analysis_id"))
    if not r["task_id"]:
        return None
    r["task_name"] = _str(data.get("app_name") or data.get("application_name", ""))
    raw_st = _str(data.get("status")).lower()
    r["status"] = _VERACODE_STATUS.get(raw_st, "unknown")
    r["started_at"] = data.get("submitted_date") or data.get("created")
    r["ended_at"] = data.get("published_date") or data.get("completed")
    r["message"] = _str(data.get("status"))
    sev = data.get("results", {}).get("severity") or data.get("severity_counts") or {}
    if isinstance(sev, dict):
        r["findings_summary"] = _severity_counts(sev, {
            "5": "CRITICAL", "4": "HIGH", "3": "MEDIUM", "2": "LOW",
            "1": "INFO", "0": "INFO",
            "Very High": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM",
            "Low": "LOW", "Very Low": "INFO", "Informational": "INFO",
        })
    r["metadata"] = {k: data[k] for k in ("app_id", "sandbox_id", "policy_name", "scan_type") if k in data}
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
    # GoPhish has no vuln-severity findings
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
    # SonarQube doesn't map to vuln severity; expose gate conditions as metadata
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

    # Snyk webhooks fire on test completion
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


# ── CodeQL (GitHub code_scanning) ────────────────────────────────────────

_CODEQL_SEVERITY = {
    "critical": "CRITICAL", "high": "HIGH", "error": "HIGH",
    "medium": "MEDIUM", "warning": "MEDIUM",
    "low": "LOW", "note": "INFO", "none": "INFO",
}


def parse_codeql(data):
    r = _empty_result("codeql")

    # check_suite / check_run events for scan lifecycle
    check_run = data.get("check_run") or {}
    check_suite = data.get("check_suite") or {}
    alert = data.get("alert") or {}
    repo = data.get("repository") or {}
    repo_name = _str(repo.get("full_name", ""))

    if check_run.get("id"):
        r["task_id"] = _str(check_run["id"])
        r["task_name"] = f"CodeQL — {repo_name}" if repo_name else "CodeQL analysis"
        cr_status = _str(check_run.get("status")).lower()
        cr_conclusion = _str(check_run.get("conclusion")).lower()
        if cr_status == "queued":
            r["status"] = "queued"
        elif cr_status == "in_progress":
            r["status"] = "running"
        elif cr_status == "completed":
            r["status"] = "complete" if cr_conclusion in ("success", "neutral") else "failed"
        r["started_at"] = check_run.get("started_at")
        r["ended_at"] = check_run.get("completed_at")
        r["message"] = f"{cr_status}" + (f" ({cr_conclusion})" if cr_conclusion else "")
    elif check_suite.get("id"):
        r["task_id"] = _str(check_suite["id"])
        r["task_name"] = f"CodeQL — {repo_name}" if repo_name else "CodeQL analysis"
        cs_status = _str(check_suite.get("status")).lower()
        cs_conclusion = _str(check_suite.get("conclusion")).lower()
        if cs_status == "queued":
            r["status"] = "queued"
        elif cs_status == "in_progress":
            r["status"] = "running"
        elif cs_status == "completed":
            r["status"] = "complete" if cs_conclusion in ("success", "neutral") else "failed"
        r["started_at"] = check_suite.get("created_at")
        r["ended_at"] = check_suite.get("updated_at") if r["status"] in ("complete", "failed") else None
        r["message"] = f"{cs_status}" + (f" ({cs_conclusion})" if cs_conclusion else "")
    elif alert.get("number"):
        # code_scanning_alert event — individual finding, not scan lifecycle
        action = _str(data.get("action"))
        r["task_id"] = f"codeql-alert-{repo_name}-{alert['number']}"
        r["task_name"] = f"CodeQL alert #{alert['number']} — {repo_name}"
        r["status"] = "complete"
        r["message"] = f"Alert {action}"
        rule = alert.get("rule") or {}
        sev = _str(rule.get("severity") or rule.get("security_severity_level", "")).lower()
        norm = _CODEQL_SEVERITY.get(sev, "INFO")
        r["findings_summary"] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        r["findings_summary"][norm] = 1
        r["metadata"] = {
            "action": action,
            "alert_number": alert.get("number"),
            "rule_id": _str(rule.get("id")),
            "state": _str(alert.get("state")),
        }
        return r
    else:
        return None

    r["metadata"] = {
        "repository": repo_name,
        "action": _str(data.get("action")),
        "sender": _str(data.get("sender", {}).get("login")),
    }
    return r


# ── Registry ─────────────────────────────────────────────────────────────

PARSERS = {
    "generic": parse_generic,
    "nessus": parse_nessus,
    "qualys": parse_qualys,
    "insightvm": parse_insightvm,
    "openvas": parse_openvas,
    "burp_enterprise": parse_burp_enterprise,
    "checkmarx": parse_checkmarx,
    "trivy": parse_trivy,
    "veracode": parse_veracode,
    "gophish": parse_gophish,
    "semgrep": parse_semgrep,
    "sonarqube": parse_sonarqube,
    "snyk": parse_snyk,
    "codeql": parse_codeql,
}

PROVIDER_NAMES = {
    "generic": "Generic",
    "nessus": "Nessus",
    "qualys": "Qualys",
    "insightvm": "InsightVM",
    "openvas": "OpenVAS",
    "burp_enterprise": "Burp Enterprise",
    "checkmarx": "Checkmarx",
    "trivy": "Trivy",
    "veracode": "Veracode",
    "gophish": "GoPhish",
    "semgrep": "Semgrep",
    "sonarqube": "SonarQube",
    "snyk": "Snyk",
    "codeql": "CodeQL",
}


def parse(provider, data):
    fn = PARSERS.get(provider)
    if fn is None:
        return None
    try:
        return fn(data)
    except Exception:
        return None
