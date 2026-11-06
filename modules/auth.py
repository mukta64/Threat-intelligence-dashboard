from modules.supabase_client import get_supabase_client


def ensure_profile(client, auth_user, preferred_username=None):
    """
    Make sure the authenticated user has a row in public.profiles.
    New profiles are always created with role='user'.
    Admin privileges must be assigned manually in Supabase SQL Editor.
    """
    user_id = auth_user.id
    email = auth_user.email or ""
    metadata = getattr(auth_user, "user_metadata", None) or {}

    username = (
        preferred_username
        or metadata.get("username")
        or (email.split("@")[0] if email else "user")
    )

    result = (
        client.table("profiles")
        .select("id, username, role")
        .eq("id", user_id)
        .execute()
    )

    rows = result.data or []
    if rows:
        return rows[0]

    client.table("profiles").insert({
        "id": user_id,
        "username": username,
        "role": "user"
    }).execute()

    result = (
        client.table("profiles")
        .select("id, username, role")
        .eq("id", user_id)
        .execute()
    )

    if not result.data:
        raise RuntimeError(
            "Your account was created, but its profile could not be loaded."
        )

    return result.data[0]


def log_audit_event(
    client,
    user,
    action,
    status,
    indicator=None,
    details=None
):
    """
    Store an audit event for the signed-in user.
    The database RLS policy must restrict inserts to auth.uid().
    """
    if not user or not user.get("id"):
        return

    payload = {
        "user_id": user["id"],
        "username": user.get("username") or user.get("email") or "user",
        "action": action,
        "indicator": indicator,
        "status": status,
        "details": details or {}
    }

    try:
        client.table("audit_logs").insert(payload).execute()
    except Exception:
        # Do not interrupt a threat investigation if audit logging fails.
        # Configure and test the audit_logs table/RLS in Supabase.
        return
