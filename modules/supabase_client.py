import os
import streamlit as st
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()


def _get_setting(name):
    value = os.getenv(name)
    if value:
        return value

    try:
        return st.secrets.get(name, "")
    except Exception:
        return ""


def get_supabase_client():
    """
    Return one Supabase client per Streamlit browser session.
    Do not use st.cache_resource here: authentication sessions must not
    be shared between different users.
    """
    url = _get_setting("SUPABASE_URL")
    key = _get_setting("SUPABASE_KEY")

    if not url or not key:
        raise RuntimeError(
            "Missing SUPABASE_URL or SUPABASE_KEY. Add them to .env "
            "locally and Streamlit Cloud Secrets after deployment."
        )

    cached_client = st.session_state.get("_supabase_client")
    cached_config = st.session_state.get("_supabase_config")

    if cached_client is not None and cached_config == (url, key):
        return cached_client

    client = create_client(url, key)
    st.session_state["_supabase_client"] = client
    st.session_state["_supabase_config"] = (url, key)
    return client
