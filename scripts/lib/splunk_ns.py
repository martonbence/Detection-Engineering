"""Which Splunk REST namespace the pipeline addresses, and why (register item 3.9).

Every Splunk object lives in a namespace addressed as `servicesNS/{owner}/{app}`,
and the `{owner}` segment is not merely how you *find* an object -- it decides
which configuration layer a write lands in. That distinction is the whole of
item 3.9.

Writing through `servicesNS/<service-account>/<app>` put every update into the
service account's private layer. Splunk does not reject that: it stores the
change as a user-level stanza *on top of* the app-level object, which is why
each rule showed up twice in the UI -- the live app-level alert, plus a private
unscheduled report doing nothing. Nothing was broken by it (the detections ran,
were scheduled, and the verification measured the real ones), but the private
copy came back on the next update no matter how often it was deleted by hand.

Writing through `servicesNS/nobody/<app>` puts the object at app level from the
moment it is created, so an update has no private layer to shadow itself with.
Measured on 2026-08-08 against the dev app, one throwaway object per arm:

    servicesNS/<account>/<app>   create -> 1 copy, then update -> 2 copies
    servicesNS/nobody/<app>      create -> 1 copy, then update -> 1 copy,
                                 already sharing=app, no HTTP 409

The obvious question -- why was this not done in the first place -- has an
answer worth keeping, because the code used to carry the wrong half of it. An
earlier attempt did try `nobody` and hit
"You do not have permission to change the owner of this object", and concluded
the namespace was unavailable to a service account without `admin_all_objects`.
The 403 is real and reproducible, but it is about the *ACL payload*, not the
path: Splunk assigns real ownership to whoever authenticates, so naming
`nobody` as the owner in an ACL POST *is* an ownership change and is refused.
Sending the authenticating user's own name instead is accepted (HTTP 200) and
still applies sharing and permissions. Hence the split below -- `nobody` in the
path, the real account in the payload -- which is the combination nobody tried.

One boundary this module cannot express, so it is stated here: `nobody` belongs
on `saved/searches` paths only. A `search/jobs` path identifies a *running job*
owned by whoever dispatched it, not a configuration object, so those URLs keep
the authenticating user and must not be routed through here.
"""

from urllib.parse import quote

# The namespace all saved-search writes go through.
NAMESPACE_OWNER = "nobody"

# Splunk's wildcard owner. A single-owner path shows one configuration layer and
# hides the other, which is precisely how the shadow objects stayed invisible to
# the pipeline for so long; this is the only view that lists both.
ALL_OWNERS = "-"


def namespace_url(base_url: str, owner: str, app: str) -> str:
    return f"{base_url.rstrip('/')}/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"


def saved_searches_url(base_url: str, app: str, owner: str = NAMESPACE_OWNER) -> str:
    """The saved-search collection endpoint -- listing and creation."""
    return f"{namespace_url(base_url, owner, app)}/saved/searches"


def saved_search_url(
    base_url: str, app: str, name: str, owner: str = NAMESPACE_OWNER
) -> str:
    """One saved search -- read, update and delete."""
    return f"{saved_searches_url(base_url, app, owner)}/{quote(name, safe='')}"
