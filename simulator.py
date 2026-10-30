"""State-diff simulator: apply decoded actions to a copy of the in-memory ledger."""
import copy

from decoder.decode import fmt_amt, meta, to_int, usd_value, who


def initial_ledger(hist, syms):
    return {
        "bal": {a: to_int(v, syms) for a, v in hist["balances"].items()},
        "allow": {(t, s): to_int(v, syms) for t, m in hist.get("allowances", {}).items() for s, v in m.items()},
        "ops": {(t, o): bool(v) for t, m in hist.get("operators", {}).items() for o, v in m.items()},
    }


def _debit(led, asset, amt, notes, ctx):
    have = led["bal"].get(asset, 0)
    if amt > have:
        notes.append(f"Balance too low: you hold {fmt_amt(have, asset, ctx)} but this needs {fmt_amt(amt, asset, ctx)}. "
                     "On a real chain it would revert.")
        amt = have
    led["bal"][asset] = have - amt


def _credit(led, asset, amt):
    led["bal"][asset] = led["bal"].get(asset, 0) + amt


def simulate(d, ctx):
    w = ctx["wallet"]
    before = ctx["ledger"]
    led = copy.deepcopy(before)
    notes, recipients, allow_keys, op_keys = [], [], set(), set()
    unmodelled = 0

    for a in d["actions"]:
        t = a["type"]
        if t in ("native_transfer", "transfer"):
            asset = "native" if t == "native_transfer" else a["token"]
            if a["from"] == w:
                _debit(led, asset, a["amount"], notes, ctx)
                if a["to"] == w:
                    _credit(led, asset, a["amount"])
                else:
                    recipients.append(a["to"])
        elif t in ("approve", "permit"):
            if a["owner"] != w:
                notes.append(f"This {t} is for {a['owner']}, not your wallet, so your allowances don't change.")
                continue
            key = (a["token"], a["spender"])
            led["allow"][key] = a["amount"]
            allow_keys.add(key)
        elif t == "approval_for_all":
            key = (a["token"], a["operator"])
            led["ops"][key] = a["approved"]
            op_keys.add(key)
        elif t == "swap":
            _debit(led, a["token_in"], a["amount_in"], notes, ctx)
            if a["recipient"] == w:
                _credit(led, a["token_out"], a["min_out"])
            else:
                recipients.append(a["recipient"])
                notes.append(f"The swap output goes to {who(a['recipient'], ctx)}, not to you.")
        else:
            unmodelled += 1

    rows, lose, gain, net = [], [], [], 0.0
    for asset in sorted(set(before["bal"]) | set(led["bal"])):
        b, a_ = before["bal"].get(asset, 0), led["bal"].get(asset, 0)
        if b == a_:
            continue
        usd = usd_value(a_ - b, asset, ctx)
        net += usd
        delta = fmt_amt(abs(a_ - b), asset, ctx)
        (gain if a_ > b else lose).append(delta)
        rows.append({"asset": asset, "symbol": meta(ctx, asset)["symbol"], "before": fmt_amt(b, asset, ctx),
                     "after": fmt_amt(a_, asset, ctx), "change": ("+" if a_ > b else "-") + delta, "usd": round(usd, 2)})

    perms, parts = [], []
    for tok, sp in sorted(allow_keys):
        b, a_ = before["allow"].get((tok, sp), 0), led["allow"].get((tok, sp), 0)
        if b == a_:
            continue
        sym = meta(ctx, tok)["symbol"]
        risk = usd_value(min(a_, led["bal"].get(tok, 0)), tok, ctx)
        perms.append({"label": f"{sym} spending allowance", "who": who(sp, ctx), "before": fmt_amt(b, tok, ctx),
                      "after": fmt_amt(a_, tok, ctx), "exposure_usd": round(risk, 2)})
        if a_ > b:
            parts.append(f"{who(sp, ctx)} gets the right to spend {fmt_amt(a_, tok, ctx)} (about ${risk:,.0f} at risk today).")
        else:
            parts.append(f"{who(sp, ctx)}'s {sym} allowance shrinks to {fmt_amt(a_, tok, ctx)}.")
    for tok, op in sorted(op_keys):
        b, a_ = before["ops"].get((tok, op), False), led["ops"].get((tok, op), False)
        if b == a_:
            continue
        sym = meta(ctx, tok)["symbol"]
        risk = usd_value(led["bal"].get(tok, 0), tok, ctx)
        perms.append({"label": f"control of all {sym} NFTs", "who": who(op, ctx), "before": "granted" if b else "not granted",
                      "after": "granted" if a_ else "not granted", "exposure_usd": round(risk if a_ else 0, 2)})
        if a_:
            parts.append(f"{who(op, ctx)} gets control of all your {sym} NFTs (about ${risk:,.0f} today).")
        else:
            parts.append(f"{who(op, ctx)} loses control of your {sym} NFTs.")

    head = []
    if lose:
        head.append("You will lose " + ", ".join(lose) + ".")
        head.append("You will receive at least " + ", ".join(gain) + "." if gain else "You get nothing back.")
    elif gain:
        head.append("You will receive " + ", ".join(gain) + ".")
    if unmodelled:
        notes.append(f"{unmodelled} step(s) couldn't be simulated, so the real effect is unknown.")
    headline = " ".join(head + parts) or "Nothing in your wallet changes."

    return {"headline": headline, "balances": rows, "approvals": perms, "notes": notes,
            "outflow_usd": round(max(0.0, -net), 2), "recipients": list(dict.fromkeys(recipients))}
