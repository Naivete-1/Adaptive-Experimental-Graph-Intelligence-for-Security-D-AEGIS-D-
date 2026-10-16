"""
Reproducible synthetic event generator.

Produces benign background traffic plus optional injected attack patterns.
Each injected pattern is the raw material for one detection rule.

Injection timing note:
The three injected patterns (brute force, privilege escalation, large
download) are placed within a ~500-second span so they cluster into a
single incident under the default 15-minute correlation window. This
models an attack *chain*, not three independent events. Real chains
vary; this is a documented simplification.
"""

import random
from datetime import datetime, timedelta, timezone
from typing import Any

from aegis.events.schema import validate_event


USERS = (
    "user:alice",
    "user:bob",
    "user:carol",
    "user:dave",
    "user:service-worker",
)
SOURCE_IPS = (
    "192.0.2.10",
    "192.0.2.20",
    "198.51.100.5",
    "203.0.113.42",
)
# Benign events only assign non-privileged roles. In this synthetic
# world, privileged role assignments are treated as unambiguous signals
# and are only produced via the privilege_escalation injection. This is a
# documented simplification; real cloud traffic contains legitimate
# privileged assignments that would require review rather than alarm.
BENIGN_ROLES = ("reader", "editor", "developer")

SUPPORTED_INJECTIONS = (
    "brute_force",
    "privilege_escalation",
    "large_download",
)


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normal_event(
    rng: random.Random,
    base: datetime,
    index: int,
) -> dict[str, Any]:
    event_type = rng.choices(
        ("login_attempt", "role_assignment", "data_download"),
        weights=(0.6, 0.15, 0.25),
    )[0]

    user = rng.choice(USERS)
    source_ip = rng.choice(SOURCE_IPS)
    ts = base + timedelta(seconds=index * rng.randint(1, 30))

    event: dict[str, Any] = {
        "event_id": f"EVT-{index:06d}",
        "timestamp": _iso(ts),
        "event_type": event_type,
        "user": user,
        "source_ip": source_ip,
    }

    if event_type == "login_attempt":
        event["success"] = rng.random() > 0.1
    elif event_type == "role_assignment":
        event["role"] = rng.choice(BENIGN_ROLES)
    elif event_type == "data_download":
        event["records"] = rng.randint(1, 500)
        event["resource"] = rng.choice(
            ("report:weekly", "dataset:analytics", "log:audit")
        )

    return event


def _inject_brute_force(
    rng: random.Random,
    base: datetime,
    start_index: int,
    *,
    attempts: int = 5,
    user: str = "user:bob",
    source_ip: str = "203.0.113.99",
) -> list[dict[str, Any]]:
    events = []
    # Attack chain begins ~17 minutes into the simulation.
    t0 = base + timedelta(seconds=1000 + rng.randint(0, 100))
    for i in range(attempts):
        events.append({
            "event_id": f"EVT-{start_index + i:06d}",
            "timestamp": _iso(t0 + timedelta(seconds=i * 20)),
            "event_type": "login_attempt",
            "user": user,
            "source_ip": source_ip,
            "success": False,
        })
    return events


def _inject_privilege_escalation(
    rng: random.Random,
    base: datetime,
    index: int,
    *,
    user: str = "user:bob",
    role: str = "cloud-admin",
) -> dict[str, Any]:
    # Occurs ~3 minutes after the brute-force burst.
    t = base + timedelta(seconds=1200 + rng.randint(0, 100))
    return {
        "event_id": f"EVT-{index:06d}",
        "timestamp": _iso(t),
        "event_type": "role_assignment",
        "user": user,
        "source_ip": "203.0.113.99",
        "role": role,
    }


def _inject_large_download(
    rng: random.Random,
    base: datetime,
    index: int,
    *,
    user: str = "user:bob",
    records: int = 20000,
) -> dict[str, Any]:
    # Occurs ~3 minutes after the escalation.
    t = base + timedelta(seconds=1400 + rng.randint(0, 100))
    return {
        "event_id": f"EVT-{index:06d}",
        "timestamp": _iso(t),
        "event_type": "data_download",
        "user": user,
        "source_ip": "203.0.113.99",
        "records": records,
        "resource": "dataset:customer-pii",
    }


def generate_events(
    count: int = 100,
    seed: int = 42,
    *,
    base_time: datetime | None = None,
    inject: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """
    Generate `count` benign events, then append any requested attack
    patterns.

    Supported injections: "brute_force", "privilege_escalation",
    "large_download".
    """
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError("count must be a positive integer")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")

    unknown = [name for name in inject if name not in SUPPORTED_INJECTIONS]
    if unknown:
        raise ValueError(f"unknown injection(s): {unknown}")

    rng = random.Random(seed)
    base = base_time or datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    events = [_normal_event(rng, base, i) for i in range(1, count + 1)]
    next_index = count + 1

    if "brute_force" in inject:
        events.extend(_inject_brute_force(rng, base, next_index))
        next_index += 5
    if "privilege_escalation" in inject:
        events.append(_inject_privilege_escalation(rng, base, next_index))
        next_index += 1
    if "large_download" in inject:
        events.append(_inject_large_download(rng, base, next_index))

    for event in events:
        validate_event(event)

    return events