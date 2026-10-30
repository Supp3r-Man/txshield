"""Decode simulated transactions and typed data into plain English plus normalized actions."""
import json
import re
from pathlib import Path

ABI = json.loads((Path(__file__).with_name("abi.json")).read_text(encoding="utf-8"))
FUNCS = {f["selector"]: f for f in ABI["functions"]}
BY_NAME = {f["name"]: f for f in ABI["functions"]}

MAX_UINT = 2**256 - 1
UNLIMITED = 2**128  # anything this big is "unlimited" for every practical purpose
MAX_HEX = 20000
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX_RE = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")
DIGITS_RE = re.compile(r"^[0-9]{1,80}$")
AMT_RE = re.compile(r"^([0-9]{1,30}(?:\.[0-9]{1,30})?) ([A-Za-z0-9]{1,12})$")


# ---------- small helpers ----------

def symbols(reg):
    out = {reg["native"]["symbol"]: reg["native"]["decimals"]}
    out.update({t["symbol"]: t["decimals"] for t in reg["tokens"].values()})
    return out


def to_int(v, syms):
    """Accepts 123, "123", "MAX" or "1.5 tETH" and returns base units."""
    if isinstance(v, bool):
        raise ValueError("expected a number, got true/false")
    if isinstance(v, int):
        n = v
    elif isinstance(v, str):
        s = v.strip()
        m = AMT_RE.match(s)
        if s.upper() == "MAX":
            n = MAX_UINT
        elif DIGITS_RE.match(s):
            n = int(s)
        elif m and m.group(2) in syms:
            whole, _, frac = m.group(1).partition(".")
            d = syms[m.group(2)]
            n = int(whole) * 10**d + int((frac + "0" * d)[:d] or 0)
        else:
            raise ValueError(f"can't read amount {v!r}")
    else:
        raise ValueError(f"can't read amount {v!r}")
    if not 0 <= n <= MAX_UINT:
        raise ValueError("amount out of range")
    return n


def norm(a):
    if not isinstance(a, str) or not ADDR_RE.match(a):
        raise ValueError(f"bad address: {a!r}")
    return a.lower()


def short(a):
    return a[:6] + "..." + a[-4:]


def meta(ctx, asset):
    if asset == "native":
        return ctx["reg"]["native"]
    return ctx["reg"]["tokens"].get(asset) or {"symbol": "unknown-token " + short(asset), "decimals": 0, "usd": 0, "type": "erc20"}


def usd_value(raw, asset, ctx):
    m = meta(ctx, asset)
    return float(raw) / 10 ** m["decimals"] * m.get("usd", 0)


def fmt_amt(raw, asset, ctx):
    m = meta(ctx, asset)
    if raw >= UNLIMITED:
        return f"UNLIMITED {m['symbol']}"
    whole, frac = divmod(raw, 10 ** m["decimals"])
    s = f"{whole:,}"
    if frac:
        s += "." + str(frac).rjust(m["decimals"], "0").rstrip("0")
    return f"{s} {m['symbol']}"


def label(a, ctx):
    if a in ctx["deny"]:
        return "DENYLISTED: " + ctx["deny"][a]
    if a == ctx["wallet"]:
        return "you"
    if a in ctx["contacts"]:
        return "your contact " + ctx["contacts"][a]
    c = ctx["reg"]["contracts"].get(a)
    if c:
        return f"{c['name']}, " + ("verified" if c.get("verified") else "unverified")
    t = ctx["reg"]["tokens"].get(a)
    if t:
        return f"{t['symbol']} token contract"
    return None


def who(a, ctx):
    lab = label(a, ctx)
    return f"{a} ({lab})" if lab else f"{a} (unknown address)"


def when(ts, now):
    d = ts - now
    if d <= 0:
        return "no longer (expired)"
    if d > 10 * 365 * 86400:
        return "forever (no practical expiry)"
    if d < 3600:
        return f"for another {max(d // 60, 1)} min"
    if d < 172800:
        return f"for another {d // 3600} h"
    return f"for another {d // 86400} days"


# ---------- tiny ABI codec (static types, bytes, dynamic arrays) ----------

def _is_dyn(t):
    return t == "bytes" or t.endswith("[]")


def _enc_static(t, v, syms):
    if t == "address":
        return bytes(12) + bytes.fromhex(norm(v)[2:])
    if t == "bool":
        if not isinstance(v, bool):
            raise ValueError("expected true/false")
        return int(v).to_bytes(32, "big")
    if t.startswith("uint"):
        return to_int(v, syms).to_bytes(32, "big")
    if t.startswith("bytes"):
        if not isinstance(v, str) or not HEX_RE.match(v):
            raise ValueError("expected 0x-hex")
        return bytes.fromhex(v[2:]).ljust(32, b"\0")
    raise ValueError(f"unsupported type {t}")


def _enc(t, v, syms):
    if t == "bytes":
        if isinstance(v, dict):
            v = encode_call(v, syms)
        if not isinstance(v, str) or not HEX_RE.match(v):
            raise ValueError("bytes must be 0x-hex or a nested call")
        b = bytes.fromhex(v[2:])
        return len(b).to_bytes(32, "big") + b + bytes(-len(b) % 32)
    if t.endswith("[]"):
        if not isinstance(v, list) or len(v) > 256:
            raise ValueError("bad array")
        return len(v).to_bytes(32, "big") + _enc_tuple([t[:-2]] * len(v), v, syms)
    return _enc_static(t, v, syms)


def _enc_tuple(types, vals, syms):
    heads, tail = [], b""
    base = 32 * len(types)
    for t, v in zip(types, vals):
        if _is_dyn(t):
            heads.append((base + len(tail)).to_bytes(32, "big"))
            tail += _enc(t, v, syms)
        else:
            heads.append(_enc(t, v, syms))
    return b"".join(heads) + tail


def encode_call(call, syms):
    """{"fn": "approve", "args": [...]} -> 0x calldata. Lets fixtures stay readable."""
    fn = BY_NAME.get(call.get("fn"))
    args = call.get("args", [])
    if not fn or not isinstance(args, list) or len(args) != len(fn["inputs"]):
        raise ValueError("call needs a known fn and matching args")
    return fn["selector"] + _enc_tuple([i["type"] for i in fn["inputs"]], args, syms).hex()


def _word(buf, off):
    w = buf[off: off + 32]
    if len(w) != 32:
        raise ValueError("calldata too short")
    return int.from_bytes(w, "big")


def _dec(t, buf, off):
    if t == "bytes":
        n = _word(buf, off)
        raw = buf[off + 32: off + 32 + n]
        if len(raw) != n:
            raise ValueError("bytes run past the end")
        return "0x" + raw.hex()
    if t.endswith("[]"):
        n = _word(buf, off)
        if n > 256:
            raise ValueError("array too long")
        return _dec_tuple([t[:-2]] * n, buf, off + 32)
    w = buf[off: off + 32]
    if len(w) != 32:
        raise ValueError("calldata too short")
    if t == "address":
        return "0x" + w[12:].hex()
    if t == "bool":
        return int.from_bytes(w, "big") != 0
    if t.startswith("uint"):
        return int.from_bytes(w, "big")
    if t.startswith("bytes"):
        return "0x" + w[: int(t[5:])].hex()
    raise ValueError(f"unsupported type {t}")


def _dec_tuple(types, buf, base):
    out = []
    for i, t in enumerate(types):
        slot = base + 32 * i
        out.append(_dec(t, buf, base + _word(buf, slot)) if _is_dyn(t) else _dec(t, buf, slot))
    return out


# ---------- decoding ----------

def decode(payload, ctx):
    """payload: {"origin"?, and one of "tx" | "typed_data" | "raw_message"}."""
    out = {"kind": None, "origin": None, "from": ctx["wallet"], "to": None, "actions": [], "lines": [], "opaque": False}
    origin = payload.get("origin")
    if origin is not None:
        if not isinstance(origin, str) or len(origin) > 100:
            raise ValueError("origin must be a short string")
        out["origin"] = origin
    if "tx" in payload:
        _tx(payload["tx"], ctx, out)
    elif "typed_data" in payload:
        _typed(payload["typed_data"], ctx, out)
    elif "raw_message" in payload:
        _raw(payload["raw_message"], out)
    else:
        raise ValueError("Expected one of: tx, typed_data, raw_message.")
    return out


def _native(out, ctx, to, value):
    out["actions"].append({"type": "native_transfer", "from": ctx["wallet"], "to": to, "amount": value})
    return f"Send {fmt_amt(value, 'native', ctx)} to {who(to, ctx)}."


def _tx(tx, ctx, out):
    if not isinstance(tx, dict):
        raise ValueError("tx must be an object")
    w, syms = ctx["wallet"], ctx["syms"]
    to = norm(tx.get("to"))
    if tx.get("from") is not None and norm(tx["from"]) != w:
        raise ValueError(f"tx.from must be the simulated wallet {w}")
    value = to_int(tx.get("value", 0), syms)
    if tx.get("data"):
        data = tx["data"]
    elif tx.get("call") is not None:
        if not isinstance(tx["call"], dict):
            raise ValueError("call must be an object")
        data = encode_call(tx["call"], syms)
    else:
        data = "0x"
    if not isinstance(data, str) or len(data) > MAX_HEX or not HEX_RE.match(data):
        raise ValueError("data must be 0x-hex")
    data = data.lower()
    out.update(kind="tx", to=to, value=value, data_bytes=(len(data) - 2) // 2)
    lines = []
    if value:
        lines.append(_native(out, ctx, to, value))
    if len(data) > 2:
        lines += _call(to, data, ctx, out, 0)
    out["lines"] += lines or ["Empty transaction: moves nothing and calls nothing."]


def _opaque(to, sel, nbytes, ctx, out):
    out["opaque"] = True
    out["actions"].append({"type": "unknown", "what": "call", "to": to, "selector": sel, "bytes": nbytes})
    return [f"Call an UNREADABLE function ({sel}, {nbytes} bytes) on {who(to, ctx)}. "
            "It isn't in the bundled ABI, so nobody can tell you what it does."]


def _call(to, data, ctx, out, depth):
    w = ctx["wallet"]
    nbytes = (len(data) - 2) // 2
    sel = data[:10]
    fn = FUNCS.get(sel)
    a = None
    if fn:
        try:
            vals = _dec_tuple([i["type"] for i in fn["inputs"]], bytes.fromhex(data[10:]), 0)
            a = {i["name"]: v for i, v in zip(fn["inputs"], vals)}
        except ValueError:
            a = None
    if a is None or depth > 1:
        return _opaque(to, sel, nbytes, ctx, out)

    kind = fn["kind"]
    sym = meta(ctx, to)["symbol"]
    if kind == "erc20_transfer":
        out["actions"].append({"type": "transfer", "token": to, "from": w, "to": a["to"], "amount": a["amount"]})
        return [f"Send {fmt_amt(a['amount'], to, ctx)} to {who(a['to'], ctx)}."]
    if kind == "approve":
        sp, amt = a["spender"], a["amount"]
        out["actions"].append({"type": "approve", "token": to, "owner": w, "spender": sp, "amount": amt})
        if amt == 0:
            return [f"Revoke {who(sp, ctx)}'s permission to spend your {sym}."]
        if amt >= UNLIMITED:
            return [f"Let {who(sp, ctx)} spend UNLIMITED {sym} from your wallet, with no end date, until you revoke it."]
        return [f"Let {who(sp, ctx)} spend up to {fmt_amt(amt, to, ctx)} of your {sym}."]
    if kind == "approval_for_all":
        op = a["operator"]
        out["actions"].append({"type": "approval_for_all", "token": to, "owner": w, "operator": op, "approved": a["approved"]})
        if a["approved"]:
            return [f"Give {who(op, ctx)} control of ALL your {sym} NFTs: every one you own now and any you get later."]
        return [f"Take back {who(op, ctx)}'s control over your {sym} NFTs."]
    if kind == "nft_transfer":
        out["actions"].append({"type": "transfer", "token": to, "from": a["from"], "to": a["to"], "amount": 1, "token_id": a["tokenId"]})
        return [f"Send NFT #{a['tokenId']} of {sym} to {who(a['to'], ctx)}."]
    if kind == "permit":
        out["actions"].append({"type": "permit", "token": to, "owner": a["owner"], "spender": a["spender"],
                               "amount": a["value"], "deadline": a["deadline"], "via": "calldata"})
        return [f"Apply a permit: let {who(a['spender'], ctx)} spend {fmt_amt(a['value'], to, ctx)} of {a['owner']}'s {sym}, "
                f"valid {when(a['deadline'], ctx['now'])}."]
    if kind == "swap":
        path = a["path"]
        if len(path) < 2:
            return _opaque(to, sel, nbytes, ctx, out)
        tin, tout = path[0], path[-1]
        out["actions"].append({"type": "swap", "router": to, "token_in": tin, "token_out": tout, "amount_in": a["amountIn"],
                               "min_out": a["amountOutMin"], "recipient": a["to"], "deadline": a["deadline"]})
        return [f"Swap {fmt_amt(a['amountIn'], tin, ctx)} for at least {fmt_amt(a['amountOutMin'], tout, ctx)}, "
                f"delivered to {who(a['to'], ctx)}, through {who(to, ctx)}. Valid {when(a['deadline'], ctx['now'])}."]
    if kind == "multicall":
        targets, values, inner = a["targets"], a["values"], a["data"]
        if not len(targets) == len(values) == len(inner):
            return _opaque(to, sel, nbytes, ctx, out)
        lines = [f"Run {len(targets)} calls from one signature:"]
        for i, (tg, val, blob) in enumerate(zip(targets, values, inner), 1):
            sub = []
            if val:
                sub.append(_native(out, ctx, tg, val))
            if len(blob) > 2:
                sub += _call(tg, blob, ctx, out, depth + 1)
            lines += [f"  {i}. {s}" for s in sub] or [f"  {i}. (empty call)"]
        return lines
    return _opaque(to, sel, nbytes, ctx, out)


def _typed(td, ctx, out):
    if not isinstance(td, dict):
        raise ValueError("typed_data must be an object")
    pt, msg, dom = td.get("primaryType"), td.get("message"), td.get("domain", {})
    if not isinstance(pt, str) or len(pt) > 64 or not isinstance(msg, dict) or not isinstance(dom, dict):
        raise ValueError("typed_data needs primaryType, domain and message")
    verifying = norm(dom["verifyingContract"]) if dom.get("verifyingContract") else None
    out.update(kind="typed_data", primary_type=pt, to=verifying)
    spec = ABI["typed_data"].get(pt)
    kind = spec["kind"] if spec else None
    w, syms, now = ctx["wallet"], ctx["syms"], ctx["now"]

    if kind == "permit":
        if verifying is None:
            raise ValueError("Permit needs domain.verifyingContract (the token).")
        sp, amt, dl = norm(msg["spender"]), to_int(msg["value"], syms), to_int(msg["deadline"], syms)
        out["actions"].append({"type": "permit", "token": verifying, "owner": norm(msg["owner"]), "spender": sp,
                               "amount": amt, "deadline": dl, "via": "signature"})
        out["lines"].append(
            f"SIGN a permit (no transaction, no gas): let {who(sp, ctx)} spend {fmt_amt(amt, verifying, ctx)} of your "
            f"{meta(ctx, verifying)['symbol']}, usable {when(dl, now)}. It stays invisible on-chain until someone cashes it in.")
    elif kind == "permit2_single":
        det = msg["details"]
        token, sp = norm(det["token"]), norm(msg["spender"])
        amt, exp, sd = to_int(det["amount"], syms), to_int(det["expiration"], syms), to_int(msg["sigDeadline"], syms)
        out["actions"].append({"type": "permit", "token": token, "owner": w, "spender": sp, "amount": amt,
                               "deadline": sd, "expires": exp, "via": "permit2"})
        out["lines"].append(
            f"SIGN a Permit2 message (no transaction, no gas): let {who(sp, ctx)} spend {fmt_amt(amt, token, ctx)} of your "
            f"{meta(ctx, token)['symbol']}. The allowance lasts {when(exp, now)}; the signature itself stays usable {when(sd, now)}.")
    elif kind == "login":
        out["lines"].append("Sign in (no funds can move): " + str(msg.get("statement", ""))[:200])
    else:
        out["opaque"] = True
        out["actions"].append({"type": "unknown", "what": "typed", "to": verifying, "selector": pt, "bytes": 0})
        out["lines"].append(f"Sign a structured message of unknown type '{pt}'. This wallet can't explain what it commits you to.")


def _raw(msg, out):
    if not isinstance(msg, str) or len(msg) > MAX_HEX or not HEX_RE.match(msg):
        raise ValueError("raw_message must be 0x-hex")
    n = (len(msg) - 2) // 2
    out.update(kind="raw_message", opaque=True)
    out["actions"].append({"type": "unknown", "what": "raw", "to": None, "selector": "raw", "bytes": n})
    out["lines"].append(f"Sign a raw {n}-byte blob (eth_sign style). Nothing here says what it authorizes; "
                        "if it's a transaction hash, it could be anything.")
