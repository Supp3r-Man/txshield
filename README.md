# txshield
🧯 Read before you sign. We'll do the reading.

A toy wallet-side firewall: paste a simulated transaction, get plain English, a red/amber/green verdict and a before/after of what you'd lose. Fake chain, fake tokens, real opinions.
## Honest disclaimer ⚠️
> [!CAUTION]
> **NEVER PROD-TESTED. FOR EDUCATION AND MVP DEMOS ONLY. DO NOT DOWNLOAD IT OR TRY IT. IF YOU DO, IT IS AT YOUR OWN RISK.**
## Run it 🏃
`pip install -r requirements.txt`, then `uvicorn app:app --port 8000`, open localhost:8000, make an account, load a sample. `python evaluate.py` grades the detectors.
## Things that went wrong while building this 🔧
- Python has no keccak in its standard library (sha3 is a different animal), so function selectors live in the bundled ABI instead of being computed.
- A perfect score was one threshold tweak away, so I left in two false alarms and two misses on purpose. `evaluate.py` names them.

Built with caffeine and a healthy distrust of "Sign" buttons.
