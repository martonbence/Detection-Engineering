import re


def slugify(text: str) -> str:
    text = (text or "").strip()
    slug = re.sub(r"[^A-Za-z0-9]+", "-", text)
    return slug.strip("-")


def saved_search_name(meta: dict) -> str:
    """
    Splunk saved-search name, derived from stable Sigma metadata (detect_id + title)
    rather than the filename -- keeps it human-readable for a SOC analyst while
    permanently decoupling the Splunk object identity from filesystem naming.
    """
    detect_id = str((meta or {}).get("detect_id") or "").strip()
    slug = slugify(str((meta or {}).get("title") or ""))

    if detect_id and slug:
        return f"{detect_id}_{slug}"
    return detect_id or slug or "unknown-rule"
