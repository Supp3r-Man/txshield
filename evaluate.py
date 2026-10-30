"""Score the detectors on fixtures/txs.json. Positive = malicious; flagged = amber or red.

Usage: python evaluate.py [policy.json]
"""
import json
import sys

import engine
import policy


def main():
    pol = policy.default()
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8") as fh:
            pol = policy.validate(json.load(fh))

    tp = fp = tn = fn = red = 0
    missed, noisy = [], []
    for fx in engine.FIXTURES:
        res = engine.analyze(engine.payload_of(fx), engine.CTX, pol)
        flagged, bad = res["verdict"] != "green", fx["label"] == "malicious"
        if bad and flagged:
            tp += 1
            red += res["verdict"] == "red"
        elif bad:
            fn += 1
            missed.append(fx)
        elif flagged:
            fp += 1
            noisy.append((fx, res))
        else:
            tn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    print(f"fixtures: {len(engine.FIXTURES)}   TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"precision: {precision:.2f}   recall: {recall:.2f}   (of the {tp} caught, {red} were hard blocks)")

    print("\nMISSED (malicious, verdict green):")
    for fx in missed or [None]:
        print("  none" if fx is None else f"  {fx['id']}  {fx['title']}\n        why it slips through: {fx['why']}")

    print("\nFALSE ALARMS (benign, flagged):")
    for fx, res in noisy or [(None, None)]:
        if fx is None:
            print("  none")
            continue
        print(f"  {fx['id']}  {fx['title']}  -> {res['verdict']}")
        for r in res["reasons"]:
            print(f"        [{r['action']}] {r['rule']}")


if __name__ == "__main__":
    main()
