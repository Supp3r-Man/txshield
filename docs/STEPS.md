# Steps

1. Wrote the fake world first: registry (tokens, prices, contracts, origins, denylist) and a wallet history with a simulated clock.
2. Built a tiny ABI codec (static types, bytes, dynamic arrays) so fixtures can be written as readable calls, encoded, and decoded again.
3. Decoder: calldata and typed data become plain English plus normalized actions (transfer, approve, permit, swap, ...).
4. Simulator: apply actions to a copy of the ledger, report before/after balances, approvals, and net USD outflow.
5. Detectors: one small function per rule, each returning findings with the addresses involved.
6. Policy engine: allow/warn/block per rule, per-address overrides, a spending limit, and escalation when warnings pile up.
7. 25 labeled fixtures, including two deliberate false alarms and two deliberate misses; `evaluate.py` reports both.
8. FastAPI + SQLite for accounts, history and per-user policy; plain HTML and vanilla JS for the three pages.
9. Next ideas: flag swaps whose recipient is not the wallet, a "first time paying this address" signal, Permit2 batch and transfer signatures.

# Interview Q&A

**1. What is blind signing and why is it dangerous?**
Signing data your wallet cannot decode: a raw hash (eth_sign), unknown calldata, or typed data of an unknown type. A signature authorizes whatever the data means, so if nobody can say what it means, you are guessing. Fixes: decode everything, refuse raw hashes, and push clear-signing descriptors so screens can describe more calls.

**2. What does good approval hygiene look like?**
Approve the amount you need, not UNLIMITED; approve only verified, established contracts; revoke after one-off use; treat setApprovalForAll as handing over the whole collection. The cost is an extra approval transaction per use, which is exactly why people click "unlimited". The fixtures keep one benign unlimited approval flagged on purpose.

**3. Why are permit signatures risky?**
EIP-2612 permit is an allowance granted by an off-chain signature. It costs no gas, leaves no on-chain trace until someone submits it, and stays valid until its deadline. A phisher collects it and waits. So we flag long deadlines, unlimited values, and spenders that do not match the site you are on.

**4. How is Permit2 different?**
You approve the Permit2 contract once per token (often unlimited), then sign small messages that grant a spender an amount and an expiry. The signature, not the approval, becomes the dangerous part, and there are two clocks: allowance expiration and signature deadline. We check both. Batch and transfer variants are out of scope here.

**5. How does address poisoning work and how do you catch it?**
The attacker sends dust from an address that shares the first and last few characters with someone you pay, hoping you copy it from history. We compare a new recipient's prefix and suffix against contacts and past recipients, and add weight when that address recently sent you dust. First-time legitimate recipients can still look similar, so it is a warning-grade signal.

**6. What are the limits of transaction simulation?**
Ours is a model: it applies only the actions the decoder understands and reports unknown steps as unmodelled. Real simulators fork chain state, but state can change before inclusion, contracts can detect simulation and behave differently, and prices are estimates. A clean simulation lowers risk; it does not certify safety.

**7. Why don't hardware wallet screens solve this?**
Small screens show addresses, hashes, or raw fields, and without clear-signing support a device may show nothing meaningful for a complex call. A second channel like this page can explain more, but if the host is compromised it can lie, so the explanation must be compared with what the device shows.

**8. How do you deal with user fatigue?**
Too many warnings train people to click through. So: few, specific rules; block only high-confidence cases; escalate when several weak signals stack; and let users override a trusted address instead of silencing a whole rule. `evaluate.py` prints false alarms next to misses so the trade-off stays visible.
