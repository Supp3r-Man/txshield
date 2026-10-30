"""JSON policy engine: findings in, allow / warn / block out."""
import copy
import json
import re
from pathlib import Path

LEVEL = {"allow": 0, "warn": 1, "block": 2}
VERDICT = {"allow": "green", "warn": "amber", "block": "red"}
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# rule id -> (title, {param: (min, max)})
RULES = {
    "unlimited_approval": ("Unlimited token approval", {}),
    "unverified_contract": ("Brand-new or unverified contract", {"min_age_days": (0, 3650)}),
    "permit_long_deadline": ("Permit that stays valid too long", {"max_days": (0, 3650)}),
    "spender_mismatch": ("Spender doesn't match the site", {}),
    "address_poisoning": ("Lookalike of an address you know", {"prefix": (1, 20), "suffix": (1, 20)}),
    "blind_signing": ("Opaque data you can't read", {}),
    "denylist": ("Destination on your denylist", {}),
    "large_value": ("Large value vs your history", {"multiple": (1, 1000), "min_usd": (0, 10**9)}),
    "spending_limit": ("Spending limit", {"per_tx_usd": (0, 10**9), "daily_usd": (0, 10**9)}),
}
DEFAULT = json.loads((Path(__file__).with_name("policy.json")).read_text(encoding="utf-8"))


def default():
    return copy.deepcopy(DEFAULT)


def meta():
    return {"rules": {k: {"title": t, "params": {n: list(r) for n, r in ps.items()}} for k, (t, ps) in RULES.items()},
            "actions": list(LEVEL)}


def _action(v):
    if v not in LEVEL:
        raise ValueError("action must be allow, warn or block")
    return v


def _num(v, lo, hi, name):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
        raise ValueError(f"{name} must be a number between {lo} and {hi}")
    return int(v) if float(v).is_integer() else v


def validate(p):
    """Return a cleaned copy of a policy or raise ValueError."""
    if not isinstance(p, dict):
        raise ValueError("Policy must be a JSON object.")
    out = {"default_action": _action(p.get("default_action", "warn")),
           "escalate_warns_at": _num(p.get("escalate_warns_at", 0), 0, 20, "escalate_warns_at"),
           "rules": {}, "overrides": []}
    rules = p.get("rules", {})
    if not isinstance(rules, dict) or set(rules) - set(RULES):
        raise ValueError("rules must be an object keyed by known rule ids.")
    for rid, (_, spec) in RULES.items():
        r = rules.get(rid, {})
        params = r.get("params", {}) if isinstance(r, dict) else None
        if not isinstance(r, dict) or not isinstance(params, dict):
            raise ValueError(f"{rid}: expected an object with optional params")
        clean = dict(DEFAULT["rules"][rid]["params"])
        for name, (lo, hi) in spec.items():
            if name in params:
                clean[name] = _num(params[name], lo, hi, f"{rid}.{name}")
        out["rules"][rid] = {"action": _action(r.get("action", out["default_action"])), "params": clean}
    ov = p.get("overrides", [])
    if not isinstance(ov, list) or len(ov) > 50:
        raise ValueError("overrides must be a list of at most 50 entries.")
    for o in ov:
        if not isinstance(o, dict) or o.get("rule") not in RULES:
            raise ValueError("Each override needs a known rule.")
        addr = o.get("address") or None
        if addr is not None and not (isinstance(addr, str) and ADDR_RE.match(addr)):
            raise ValueError("Override address must be a 0x address (or empty for the whole rule).")
        out["overrides"].append({"rule": o["rule"], "address": addr.lower() if addr else None, "action": _action(o.get("action"))})
    return out


def resolve_action(policy, f):
    act = policy["rules"].get(f["rule"], {}).get("action", policy["default_action"])
    for o in policy["overrides"]:
        if o["rule"] == f["rule"] and (o["address"] is None or o["address"] in f["addresses"]):
            act = o["action"]  # last matching override wins
    return act


def spending_findings(sim, ctx, p):
    out, usd = [], sim["outflow_usd"]
    per_tx, daily = p.get("per_tx_usd"), p.get("daily_usd")
    if per_tx is not None and usd > per_tx:
        out.append({"rule": "spending_limit", "addresses": sim["recipients"],
                    "message": f"This moves about ${usd:,.0f} out, over your ${per_tx:,.0f} per-transaction limit."})
    spent = ctx["daily_spent_usd"]
    if daily is not None and spent + usd > daily:
        out.append({"rule": "spending_limit", "addresses": sim["recipients"],
                    "message": f"You've already sent about ${spent:,.0f} in the last 24h; this takes you to ${spent + usd:,.0f}, "
                               f"over your ${daily:,.0f} daily limit."})
    return out


def decide(findings, sim, ctx, policy):
    findings = findings + spending_findings(sim, ctx, policy["rules"]["spending_limit"]["params"])
    reasons = [{**f, "title": RULES[f["rule"]][0], "action": resolve_action(policy, f)} for f in findings]
    reasons.sort(key=lambda r: -LEVEL[r["action"]])
    blocks = sum(r["action"] == "block" for r in reasons)
    warns = sum(r["action"] == "warn" for r in reasons)
    n = policy["escalate_warns_at"]
    escalated = blocks == 0 and n > 0 and warns >= n
    top = "block" if blocks or escalated else "warn" if warns else "allow"
    return {"decision": top, "verdict": VERDICT[top], "escalated": escalated, "reasons": reasons}
