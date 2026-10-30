"""One small function per rule. Each returns findings: {"message", "addresses"}."""
from decoder.decode import UNLIMITED, meta, short, when, who


def _f(msg, *addrs):
    return {"message": msg, "addresses": [a for a in addrs if a]}


def _grantee(a):
    """Who gets spending power from this action, if it grants any."""
    t = a["type"]
    if t in ("approve", "permit") and a["amount"] > 0:
        return a["spender"]
    if t == "approval_for_all" and a["approved"]:
        return a["operator"]
    return None


def addresses_in(d):
    seen = []
    for src in [d] + d["actions"]:
        for k in ("to", "spender", "operator", "recipient", "router", "token"):
            v = src.get(k)
            if isinstance(v, str) and v not in seen:
                seen.append(v)
    return seen


def unlimited_approval(d, sim, ctx, p):
    out = []
    for a in d["actions"]:
        sym = meta(ctx, a["token"])["symbol"] if "token" in a else ""
        if a["type"] in ("approve", "permit") and a["amount"] >= UNLIMITED:
            out.append(_f(f"{who(a['spender'], ctx)} would get an UNLIMITED {sym} allowance: every {sym} you hold now or later.", a["spender"]))
        elif a["type"] == "approval_for_all" and a["approved"]:
            out.append(_f(f"{who(a['operator'], ctx)} would control ALL your {sym} NFTs, including ones you receive later.", a["operator"]))
    return out


def unverified_contract(d, sim, ctx, p):
    min_age = p.get("min_age_days", 30)
    targets = []
    for a in d["actions"]:
        if _grantee(a):
            targets.append(_grantee(a))
        elif a["type"] == "swap":
            targets.append(a["router"])
        elif a["type"] == "unknown" and a.get("to"):
            targets.append(a["to"])
    out = []
    for t in targets:
        c = ctx["reg"]["contracts"].get(t)
        why = []
        if c is None:
            why.append("is not a contract your wallet knows (no verified source, no history)")
        else:
            if not c.get("verified"):
                why.append("has unverified source code")
            if c.get("age_days", 0) < min_age:
                why.append(f"was deployed only {c.get('age_days', 0)} days ago")
        if why:
            out.append(_f(f"{who(t, ctx)} " + " and ".join(why) + ".", t))
    return out


def permit_long_deadline(d, sim, ctx, p):
    limit = p.get("max_days", 30) * 86400
    out = []
    for a in d["actions"]:
        if a["type"] != "permit":
            continue
        far = max(x for x in (a.get("deadline"), a.get("expires"), 0) if x is not None)
        if far - ctx["now"] > limit:
            out.append(_f(f"This permit stays usable {when(far, ctx['now'])}. A signature isn't visible on-chain until "
                          "someone cashes it in, so long deadlines are how phishers wait you out.", a["spender"]))
    return out


def spender_mismatch(d, sim, ctx, p):
    site = ctx["reg"].get("origins", {}).get(d.get("origin") or "")
    if not site:
        return []
    out = []
    for a in d["actions"]:
        sp = _grantee(a)
        if sp and sp not in site["contracts"]:
            names = ", ".join(ctx["reg"]["contracts"].get(c, {}).get("name", short(c)) for c in site["contracts"])
            out.append(_f(f"You're on {d['origin']}, which normally only uses {names}, but this hands access to {who(sp, ctx)}.", sp))
    return out


def address_poisoning(d, sim, ctx, p):
    n, m = int(p.get("prefix", 4)), int(p.get("suffix", 4))
    out = []
    for a in d["actions"]:
        if a["type"] not in ("transfer", "native_transfer") or a["from"] != ctx["wallet"]:
            continue
        r = a["to"]
        if r in ctx["known"]:
            continue
        for k, name in ctx["known"].items():
            if r[2:2 + n] == k[2:2 + n] and r[-m:] == k[-m:]:
                dust = " It also sent you a zero-value 'dust' transfer recently, the classic poisoning move." if r in ctx["dust"] else ""
                out.append(_f(f"{r} starts and ends like {name} ({k}) but is a different address.{dust} "
                              "Compare the middle characters before sending.", r))
                break
    return out


def blind_signing(d, sim, ctx, p):
    out = []
    for a in d["actions"]:
        if a["type"] != "unknown":
            continue
        if a.get("what") == "raw":
            msg = "You're being asked to sign a raw blob. Whatever it commits you to, your wallet can't show it."
        elif a.get("what") == "typed":
            msg = f"The message type '{a['selector']}' isn't one this wallet can explain. You'd be signing blind."
        else:
            msg = f"Calldata {a['selector']} ({a['bytes']} bytes) isn't in the ABI, so nobody can tell you what this call does."
        out.append(_f(msg, a.get("to")))
    return out


def denylist(d, sim, ctx, p):
    return [_f(f"{a} is on your local denylist: {ctx['deny'][a]}.", a) for a in addresses_in(d) if a in ctx["deny"]]


def large_value(d, sim, ctx, p):
    mult, min_usd = p.get("multiple", 3), p.get("min_usd", 1000)
    past = [h["usd"] for h in ctx["hist"]["history"] if h["dir"] == "out"]
    basis = max(past) if past else 0
    usd = sim["outflow_usd"]
    if usd >= min_usd and usd > mult * basis:
        ratio = f"{usd / basis:.1f}x your biggest past outflow (${basis:,.0f})" if basis else "with no history to compare against"
        return [_f(f"This moves about ${usd:,.0f} out of your wallet, {ratio}.", *sim["recipients"])]
    return []


DETECTORS = {
    "unlimited_approval": unlimited_approval,
    "unverified_contract": unverified_contract,
    "permit_long_deadline": permit_long_deadline,
    "spender_mismatch": spender_mismatch,
    "address_poisoning": address_poisoning,
    "blind_signing": blind_signing,
    "denylist": denylist,
    "large_value": large_value,
}


def run_all(d, sim, ctx, policy):
    out, seen = [], set()
    for rule, fn in DETECTORS.items():
        for f in fn(d, sim, ctx, policy["rules"][rule]["params"]):
            key = (rule, f["message"])
            if key not in seen:
                seen.add(key)
                out.append({"rule": rule, **f})
    return out
