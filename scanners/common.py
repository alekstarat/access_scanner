from datetime import datetime, timezone


def finding(
        finding_id,
        severity,
        title,
        evidence="",
        description=""
):
    return {
        "id": finding_id,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "description": description
    }



def result(
        service,
        port,
        protocol,
        observations=None,
        findings=None,
):
    return { "timestamp": datetime.now(timezone.utc).isoformat(),
             "service": service,
             "port": port,
             "protocol": protocol,
             "observations": observations or {},
             "findings": findings or [],
            }