"""Command line entry point:  python -m src.cli <command>

  gen-cdr      generate synthetic CDR + ground truth
  gen-iam      generate synthetic identity events + ground truth
  detect-cdr   run CDR detection rules
  detect-iam   run identity detection rules
  evaluate     score both detectors against the injected ground truth
  demo         run everything end to end (generate -> detect -> evaluate)
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import pandas as pd

from src.common.config import load_yaml
from src.detection import cdr_detection, iam_detection
from src.iam.realm import load_user_roles
from src.synth import generate_cdr, generate_iam_events

D = Path("data/synthetic")
OUT = Path("out")


def gen_cdr(a):
    df, truth = generate_cdr.generate(seed=a.seed, hours=a.hours)
    D.mkdir(parents=True, exist_ok=True)
    df.to_csv(D / "cdr.csv", index=False)
    truth.to_csv(D / "cdr_truth.csv", index=False)
    print(f"wrote {len(df):,} synthetic CDR rows -> {D / 'cdr.csv'}")


def gen_iam(a):
    events, truth = generate_iam_events.generate(seed=a.seed)
    D.mkdir(parents=True, exist_ok=True)
    (D / "iam_events.jsonl").write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    (D / "iam_truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    print(f"wrote {len(events)} synthetic identity events -> {D / 'iam_events.jsonl'}")


def detect_cdr(a):
    cfg = load_yaml(a.config)["cdr"]
    alerts = cdr_detection.run_detection(pd.read_csv(a.input), cfg)
    OUT.mkdir(exist_ok=True)
    alerts.to_csv(OUT / "cdr_alerts.csv", index=False)
    print(f"{len(alerts)} CDR alert windows -> {OUT / 'cdr_alerts.csv'}")
    return alerts


def detect_iam(a):
    cfg = load_yaml(a.config)["iam"]
    events = [json.loads(l) for l in Path(a.events).read_text(encoding="utf-8").splitlines() if l.strip()]
    alerts = iam_detection.detect_iam(events, cfg, load_user_roles(), load_yaml("roles.yaml"))
    OUT.mkdir(exist_ok=True)
    alerts.to_csv(OUT / "iam_alerts.csv", index=False)
    print(f"{len(alerts)} identity alerts -> {OUT / 'iam_alerts.csv'}")
    return alerts


def _print_eval(title, r):
    print(f"\n== {title}: {r['detected']}/{r['total']} injected scenarios detected, "
          f"{r['alerts']} alerts, {r['alerts_unmatched']} not tied to an injected scenario ==")
    for s in r["scenarios"]:
        print(f"  {'OK ' if s['detected'] else 'MISS'} {s['scenario']:<28} rules: {', '.join(s['rules_hit']) or '-'}")


def evaluate(a):
    cdr_a = pd.read_csv(OUT / "cdr_alerts.csv")
    _print_eval("CDR detection", cdr_detection.evaluate(cdr_a, pd.read_csv(D / "cdr_truth.csv")))
    iam_a = pd.read_csv(OUT / "iam_alerts.csv", parse_dates=["window_start", "window_end"])
    truth = json.loads((D / "iam_truth.json").read_text(encoding="utf-8"))
    _print_eval("Identity detection", iam_detection.evaluate_iam(iam_a, truth))
    print("\nNote: scores are against scenarios injected into SYNTHETIC data; they show the rules work as designed, "
          "not real-world accuracy.")


def main():
    p = argparse.ArgumentParser(prog="src.cli", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen-cdr"); g.add_argument("--seed", type=int, default=7); g.add_argument("--hours", type=int, default=6); g.set_defaults(f=gen_cdr)
    g = sub.add_parser("gen-iam"); g.add_argument("--seed", type=int, default=11); g.set_defaults(f=gen_iam)
    g = sub.add_parser("detect-cdr"); g.add_argument("--input", default=str(D / "cdr.csv")); g.add_argument("--config", default="rules.yaml"); g.set_defaults(f=detect_cdr)
    g = sub.add_parser("detect-iam"); g.add_argument("--events", default=str(D / "iam_events.jsonl")); g.add_argument("--config", default="rules.yaml"); g.set_defaults(f=detect_iam)
    g = sub.add_parser("evaluate"); g.set_defaults(f=evaluate)
    g = sub.add_parser("demo"); g.set_defaults(f=None)
    a = p.parse_args()
    if a.cmd == "demo":
        ns = argparse.Namespace(seed=7, hours=6, input=str(D / "cdr.csv"), config="rules.yaml",
                                events=str(D / "iam_events.jsonl"))
        gen_cdr(ns); ns.seed = 11; gen_iam(ns); detect_cdr(ns); detect_iam(ns); evaluate(ns)
    else:
        a.f(a)


if __name__ == "__main__":
    main()
