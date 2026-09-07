"""Ranking for the picker. Pure: no I/O, no clock, no vault.

Everything here takes entry *paths* -- never a secret, never a field value --
plus the frecency table and the focused window, and returns an order. It is a
separate module so it can be tested exhaustively at tier 1, where a test costs
nothing to run.

The rule the whole file serves:

    WHAT YOU TYPED ALWAYS WINS. WHAT YOU USE BREAKS TIES.

Match tier dominates the sort; frecency and window context only order entries
that tied. Without that, a credential you use hourly could outrank the one you
just typed the exact name of, which is the kind of surprise that makes a picker
untrustworthy. The one exception is an empty query, where there is nothing to
have typed, so frecency and context are all there is.
"""

import math
import re

# Match tiers. Gaps are wide so no accumulation of tie-breakers can cross them.
EXACT_TITLE      = 1000
TITLE_PREFIX     = 800
TITLE_WORD       = 600
TITLE_SUBSTRING  = 400
PATH_SUBSTRING   = 200
MATCHED_ELSEWHERE = 100      # so: on username or URL, which we never fetch

# How a result explains itself in the list.
BY_TITLE = "title"
BY_PATH = "path"
BY_USERNAME = "username"
BY_URL = "url"
BY_OTHER = "elsewhere"      # so: notes, or a custom field -- never shown

FRECENCY_HALF_LIFE_DAYS = 14.0


def split_path(path):
    """`/Work/Mail/GitHub` -> ("GitHub", "/Work/Mail")."""
    text = str(path)
    cut = text.rfind("/")
    if cut < 0:
        return text, ""
    return text[cut + 1:], text[:cut] or "/"


def match_tier(path, term):
    """Which tier this path matches `term` at, and how it explains itself."""
    if not term:
        return PATH_SUBSTRING, BY_PATH

    title, group = split_path(path)
    low_title, low_term, low_group = title.lower(), term.lower(), group.lower()

    if low_title == low_term:
        return EXACT_TITLE, BY_TITLE
    if low_title.startswith(low_term):
        return TITLE_PREFIX, BY_TITLE
    # A term that starts a word inside the title: "hub" should not beat "git"
    # for "GitHub", but "Mail" in "Work Mail" should beat a mid-word hit.
    if re.search(r"(?:^|[\s\-_./])" + re.escape(low_term), low_title):
        return TITLE_WORD, BY_TITLE
    if low_term in low_title:
        return TITLE_SUBSTRING, BY_TITLE
    if low_term in low_group:
        return PATH_SUBSTRING, BY_PATH
    # keepassxc-cli returned it, but neither the title nor the group contains
    # the term -- so it matched on the username or the URL. We do not fetch
    # those, and we do not need to: saying "matched elsewhere" is the whole
    # point. A lookalike URL is exactly how the wrong entry ends up looking
    # right.
    return MATCHED_ELSEWHERE, BY_OTHER


def explain(path, term, username="", url=""):
    """Which field actually matched, once the metadata is known.

    Ranking happens on the path alone -- a title match must win regardless of
    what any other field says. This runs afterwards, on the handful of rows
    that will actually be shown, and only refines the label.

    Notes are searched by keepassxc-cli and are NOT passed in here on purpose:
    they routinely hold PINs, PUKs and recovery codes. An entry that matched
    nothing visible therefore matched its notes, and saying so is all the
    picker will ever say about them.
    """
    if not term:
        return BY_TITLE
    tier, why = match_tier(path, term)
    if tier > MATCHED_ELSEWHERE:
        return why
    low = term.lower()
    if low in str(username or "").lower():
        return BY_USERNAME
    if low in str(url or "").lower():
        return BY_URL
    return BY_OTHER


def frecency_bonus(path, frecency, now):
    """Recent, repeated use. Bounded, and only ever a tie-breaker."""
    if not frecency:
        return 0.0
    row = frecency.get(str(path))
    if not row:
        return 0.0
    count = max(0, int(row.get("count", 0)))
    if count == 0:
        return 0.0
    age_days = max(0.0, (now - float(row.get("last_used", 0))) / 86400.0)
    decay = 0.5 ** (age_days / FRECENCY_HALF_LIFE_DAYS)
    return 60.0 * math.log2(1 + count) * decay


def window_bonus(path, window):
    """KeePassXC's near-zero-config heuristic: is the entry title in the window title?

    A boost, never a filter. A filter that guesses wrong hides the entry you
    want and gives you no way to tell why.
    """
    if not window:
        return 0.0
    title, _ = split_path(path)
    low_title = title.lower().strip()
    if len(low_title) < 3:
        return 0.0        # "Fi" would match half the desktop

    window_title = str(window.get("title") or "").lower()
    window_class = str(window.get("class") or "").lower()

    if low_title in window_title:
        return 80.0
    if low_title in window_class or window_class in low_title:
        return 50.0
    return 0.0


def rank(paths, term, frecency=None, window=None, now=0.0, limit=None):
    """Order `paths` for `term`. Returns dicts, never bare strings.

    `limit` is applied AFTER ranking. Applying it before -- which is what
    taking the head of keepassxc-cli's tree-ordered output amounts to -- can
    hide the entry you want among hundreds of matches with no indication that
    it exists.
    """
    scored = []
    for path in paths:
        title, group = split_path(path)
        tier, why = match_tier(path, term)
        bonus = frecency_bonus(path, frecency, now) + window_bonus(path, window)
        scored.append({
            "path": str(path),
            "title": title,
            "group": group or "/",
            "tier": tier,
            "why": why,
            "bonus": bonus,
        })

    if term:
        # Tier first, so what you typed wins; bonus only orders within a tier.
        key = lambda r: (-r["tier"], -r["bonus"], len(r["title"]), r["title"].lower())
    else:
        # Nothing was typed, so use and context are all there is to go on.
        key = lambda r: (-r["bonus"], r["title"].lower())

    scored.sort(key=key)
    total = len(scored)
    if limit is not None:
        scored = scored[:limit]
    return scored, total


def merge(primary, secondary):
    """Combine two candidate lists, keeping the first occurrence of each path.

    The index answers title and path matching instantly; keepassxc-cli's own
    search is what finds username and URL hits. Both feed the same ranking.
    """
    seen, out = set(), []
    for path in list(primary) + list(secondary):
        text = str(path)
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def touch(frecency, path, now):
    """Record one use. Returns a new table; does not mutate the old one."""
    table = dict(frecency or {})
    row = dict(table.get(str(path), {}))
    row["count"] = int(row.get("count", 0)) + 1
    row["last_used"] = float(now)
    table[str(path)] = row
    return table


def prune(frecency, now, keep=500, max_age_days=365):
    """Keep the table small and current.

    It is a plaintext record of which credentials you use, so it should not
    grow without bound or remember things you stopped using a year ago.
    """
    rows = []
    for path, row in (frecency or {}).items():
        age_days = (now - float(row.get("last_used", 0))) / 86400.0
        if age_days > max_age_days:
            continue
        rows.append((path, row, frecency_bonus(path, {path: row}, now)))
    rows.sort(key=lambda r: -r[2])
    return {path: row for path, row, _ in rows[:keep]}
