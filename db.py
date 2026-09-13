import sqlite3
import pandas as pd
from sample_data import generate_alerts

DB_PATH = "mitre_dashboard.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            timestamp TEXT,
            alert_name TEXT,
            raw_log TEXT,
            technique_id TEXT,
            ioc_type TEXT,
            ioc_value TEXT,
            host TEXT,
            host_ip TEXT,
            user TEXT,
            severity TEXT,
            status TEXT,
            analyst_notes TEXT
        )
    """)
    conn.commit()
    count = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
    if count == 0:
        seed_alerts(conn)
    conn.close()


def seed_alerts(conn, n=42):
    alerts = generate_alerts(n=n)
    conn.executemany(
        """INSERT OR REPLACE INTO alerts
           (id, timestamp, alert_name, raw_log, technique_id, ioc_type, ioc_value,
            host, host_ip, user, severity, status, analyst_notes)
           VALUES (:id, :timestamp, :alert_name, :raw_log, :technique_id, :ioc_type,
                   :ioc_value, :host, :host_ip, :user, :severity, :status, :analyst_notes)""",
        alerts,
    )
    conn.commit()


def get_all_alerts_df():
    conn = get_conn()
    df = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
    conn.close()
    return df


def get_alert(alert_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_alerts_for_host(host, exclude_id=None):
    conn = get_conn()
    if exclude_id:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE host = ? AND id != ? ORDER BY timestamp",
            (host, exclude_id),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE host = ? ORDER BY timestamp", (host,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_alert(alert_id, status=None, analyst_notes=None):
    conn = get_conn()
    if status is not None:
        conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    if analyst_notes is not None:
        conn.execute("UPDATE alerts SET analyst_notes = ? WHERE id = ?", (analyst_notes, alert_id))
    conn.commit()
    conn.close()


def reset_db():
    conn = get_conn()
    conn.execute("DELETE FROM alerts")
    conn.commit()
    seed_alerts(conn)
    conn.close()
