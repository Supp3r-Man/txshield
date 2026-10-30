"""Glue: load fixtures, build the wallet context, run decode -> simulate -> detect -> decide."""
import json
from pathlib import Path

import policy as pol
from decoder.decode import decode, symbols
from detectors.rules import run_all
from simulator import initial_ledger, simulate

ROOT = Path(__file__).parent


def _load(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def resolve(o, names):
    """Swap "@alice"-style aliases for addresses (keys and values). Fixture convenience only."""
    if isinstance(o, str):
        return names.get(o[1:], o) if o.startswith("@") else o
    if isinstance(o, list):
        return [resolve(x, names) for x in o]
    if isinstance(o, dict):
        return {resolve(k, names): resolve(v, names) for k, v in o.items()}
    return o


def build_ctx():
    raw = _load("fixtures/registry.json")
    names = raw.pop("aliases")
    reg = resolve(raw, names)
    hist = resolve(_load("fixtures/wallet_history.json"), names)
    now = hist["now"]
    contacts = {c["address"]: c["name"] for c in hist["contacts"]}
    known = dict(contacts)
    for h in hist["history"]:
        if h["dir"] == "out" and h["type"] == "transfer":
            known.setdefault(h["counterparty"], "someone you've paid before")
    ctx = {
        "reg": reg, "hist": hist, "wallet": hist["wallet"], "now": now, "syms": symbols(reg),
        "contacts": contacts, "known": known,
        "dust": {h["counterparty"] for h in hist["history"] if h["dir"] == "in" and h["usd"] < 1},
        "deny": {e["address"]: e["reason"] for e in reg["denylist"]},
        "daily_spent_usd": sum(h["usd"] for h in hist["history"] if h["dir"] == "out" and h["ts"] >= now - 86400),
    }
    ctx["ledger"] = initial_ledger(hist, ctx["syms"])
    return ctx, names


CTX, ALIASES = build_ctx()
FIXTURES = resolve(_load("fixtures/txs.json"), ALIASES)["txs"]


def payload_of(fx):
    return {k: fx[k] for k in ("origin", "tx", "typed_data", "raw_message") if k in fx}


def jsonable(o):
    """Big ints become strings so JavaScript doesn't round them."""
    if isinstance(o, bool):
        return o
    if isinstance(o, int):
        return str(o) if abs(o) > 2**53 else o
    if isinstance(o, dict):
        return {str(k): jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [jsonable(x) for x in o]
    return o


def analyze(payload, ctx, policy):
    try:
        d = decode(payload, ctx)
        sim = simulate(d, ctx)
        verdict = pol.decide(run_all(d, sim, ctx, policy), sim, ctx, policy)
    except (KeyError, TypeError, AttributeError, IndexError, RecursionError) as e:
        raise ValueError(f"Malformed input ({type(e).__name__}: {e}).") from e
    return jsonable({
        "verdict": verdict["verdict"], "decision": verdict["decision"], "escalated": verdict["escalated"],
        "summary": d["lines"],
        "decoded": {k: d.get(k) for k in ("kind", "origin", "to", "primary_type", "opaque", "actions")},
        "diff": sim, "reasons": verdict["reasons"],
    })
