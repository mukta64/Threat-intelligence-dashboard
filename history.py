
import sqlite3

DB_NAME = "threat_history.db"


def save_history(record):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            indicator TEXT,
            source TEXT,
            malicious TEXT,
            suspicious TEXT,
            harmless TEXT,
            undetected TEXT,
            abuse_score TEXT,
            total_reports TEXT,
            country TEXT
        )
    """)

    cursor.execute("""
        INSERT INTO investigations (
            date, indicator, source, malicious,
            suspicious, harmless, undetected,
            abuse_score, total_reports, country
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record.get("Date", ""),
        record.get("Indicator", ""),
        record.get("Source", ""),
        str(record.get("Malicious", "")),
        str(record.get("Suspicious", "")),
        str(record.get("Harmless", "")),
        str(record.get("Undetected", "")),
        str(record.get("Abuse Score", "")),
        str(record.get("Total Reports", "")),
        str(record.get("Country", ""))
    ))

    conn.commit()
    conn.close()


def get_history():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            indicator TEXT,
            source TEXT,
            malicious TEXT,
            suspicious TEXT,
            harmless TEXT,
            undetected TEXT,
            abuse_score TEXT,
            total_reports TEXT,
            country TEXT
        )
    """)

    cursor.execute("""
        SELECT date, indicator, source, malicious,
        suspicious, harmless, undetected,
        abuse_score, total_reports, country
        FROM investigations
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    columns = [
        "Date", "Indicator", "Source", "Malicious",
        "Suspicious", "Harmless", "Undetected",
        "Abuse Score", "Total Reports", "Country"
    ]

    return [dict(zip(columns, row)) for row in rows]