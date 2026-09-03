from database import connect

SEVERITY_POINTS = {
    0: 0,
    1: 5,
    2: 12,
    3: 25,
    4: 40,
}

SENSITIVE_PORTS = {
    21: 5,
    23: 10,
    445: 10,
    3389: 10,
    5900: 8,
}


def calculate_host_score(conn, host_id: int) -> int:
    rows = conn.execute(
        """
        SELECT finding_key, severity
        FROM findings
        WHERE host_id = ?
        """,
        (host_id,),
    ).fetchall()

    points = 0
    seen = set()

    for row in rows:
        finding_key = row["finding_key"] if hasattr(row, "keys") else row[0]
        severity = row["severity"] if hasattr(row, "keys") else row[1]
        if finding_key in seen:
            continue
        seen.add(finding_key)
        points += SEVERITY_POINTS.get(severity, 0)

    ports = conn.execute(
        """
        SELECT DISTINCT port
        FROM service_observations
        WHERE host_id = ?
        """,
        (host_id,),
    ).fetchall()

    for row in ports:
        port = row["port"] if hasattr(row, "keys") else row[0]
        points += SENSITIVE_PORTS.get(port, 0)

    return min(points, 100)


def update_host_score(host_id: int, conn=None) -> int:
    """
    Если передан conn — используем его (без второго соединения).
    Иначе открываем своё.
    """
    own = conn is None
    if own:
        conn = connect()

    try:
        score = calculate_host_score(conn, host_id)
        conn.execute(
            "UPDATE hosts SET risk_score = ? WHERE id = ?",
            (score, host_id),
        )
        if own:
            conn.commit()
        return score
    finally:
        if own:
            conn.close()


def risk_level(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"