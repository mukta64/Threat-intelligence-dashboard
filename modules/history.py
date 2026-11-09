
from datetime import datetime, timezone

from modules.supabase_client import get_supabase_client


def safe_integer(value):
    """Convert numeric values to integers; use NULL for missing values."""

    if value is None or value == "":
        return None

    try:
        return int(float(value))
    except (ValueError, TypeError, OverflowError):
        return None


def save_history(record, user_id):
    """Save an investigation result for the signed-in user."""

    if not user_id:
        raise ValueError("User ID is required.")

    if not isinstance(record, dict):
        raise ValueError("Investigation record must be a dictionary.")

    client = get_supabase_client()

    payload = {
        "user_id": user_id,
        "indicator": str(record.get("Indicator", "")),
        "indicator_type": str(record.get("Indicator Type", "")),
        "source": str(record.get("Source", "")),

        # Integer columns: missing values are stored as NULL.
        "malicious": safe_integer(record.get("Malicious")),
        "suspicious": safe_integer(record.get("Suspicious")),
        "harmless": safe_integer(record.get("Harmless")),
        "undetected": safe_integer(record.get("Undetected")),
        "abuse_score": safe_integer(record.get("Abuse Score")),
        "total_reports": safe_integer(record.get("Total Reports")),

        "country": str(record.get("Country") or "")
    }

    client.table("investigations").insert(payload).execute()

    return True


def get_history(user_id):
    """Get only the investigations belonging to the signed-in user."""

    if not user_id:
        return []

    client = get_supabase_client()

    result = (
        client.table("investigations")
        .select(
            "created_at, indicator, indicator_type, source, "
            "malicious, suspicious, harmless, undetected, "
            "abuse_score, total_reports, country"
        )
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .limit(1000)
        .execute()
    )

    history = []

    for row in result.data or []:
        created_at = row.get("created_at", "")

        if created_at:
            try:
                parsed = datetime.fromisoformat(
                    created_at.replace("Z", "+00:00")
                )
                date_value = parsed.astimezone(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
            except (ValueError, AttributeError):
                date_value = str(created_at)
        else:
            date_value = ""

        history.append({
            "Date": date_value,
            "Indicator": row.get("indicator", ""),
            "Indicator Type": row.get("indicator_type", ""),
            "Source": row.get("source", ""),
            "Malicious": row.get("malicious"),
            "Suspicious": row.get("suspicious"),
            "Harmless": row.get("harmless"),
            "Undetected": row.get("undetected"),
            "Abuse Score": row.get("abuse_score"),
            "Total Reports": row.get("total_reports"),
            "Country": row.get("country", "")
        })

    return history
