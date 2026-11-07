
def ensure_profile(client, auth_user, preferred_username=None):
    """
    Get the user's profile or create one.
    New accounts always receive the user role.
    """

    if not auth_user or not auth_user.id:
        raise ValueError("Authenticated user information is missing.")

    user_id = auth_user.id
    email = auth_user.email or ""

    metadata = getattr(auth_user, "user_metadata", None) or {}

    username = (
        preferred_username
        or metadata.get("username")
        or (email.split("@")[0] if email else "user")
    )

    # Check whether this user's profile already exists.
    result = (
        client.table("profiles")
        .select("id, username, role")
        .eq("id", user_id)
        .maybe_single()
        .execute()
    )

    if result.data:
        return result.data

    # Create a profile for a new user.
    client.table("profiles").insert({
        "id": user_id,
        "username": username,
        "role": "user"
    }).execute()

    # Read the newly created profile.
    result = (
        client.table("profiles")
        .select("id, username, role")
        .eq("id", user_id)
        .single()
        .execute()
    )

    if not result.data:
        raise RuntimeError("Could not load your user profile.")

    return result.data


def log_audit_event(
    client,
    user,
    action,
    status,
    indicator=None,
    details=None
):
    """Save an audit event for the currently authenticated user."""

    if not user or not user.get("id"):
        return {
            "success": False,
            "error": "Authenticated user ID is missing."
        }

    payload = {
        "user_id": user["id"],
        "username": user.get("username") or user.get("email") or "user",
        "action": action,
        "status": status,
        "indicator": indicator,
        "details": details or {}
    }

    try:
        response = (
            client.table("audit_logs")
            .insert(payload)
            .execute()
        )

        return {
            "success": True,
            "data": response.data or []
        }

    except Exception as exc:
        return {
            "success": False,
            "error": str(exc)
        }
