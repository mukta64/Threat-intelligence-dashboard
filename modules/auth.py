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
    """Insert one audit event and return a visible success/error result."""
    if not user or not user.get("id"):
        return {"success": False, "error": "No authenticated user ID was supplied."}

    payload = {
        "user_id": user["id"],
        "username": user.get("username") or user.get("email") or "user",
        "action": action,
        "indicator": indicator,
        "status": status,
        "details": details or {}
    }

    try:
        response = client.table("audit_logs").insert(payload).execute()
        return {"success": True, "data": response.data or []}
    except Exception as exc:
        # Return the real Supabase error instead of silently hiding it.
        return {"success": False, "error": str(exc)}
