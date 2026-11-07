"""Synthetic SMS CDR generator with injected fraud scenarios and ground truth.

All names, numbers and prices are fictional. Nothing here is derived from real traffic.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import numpy as np
import pandas as pd

COUNTRIES = {
    "ID": dict(name="Indonesia", cc="62", prefixes=["811", "812", "813", "821", "852", "857", "878", "881", "895", "896"],
               tail=8, price=0.015, cost=0.012, networks=["NetA-ID", "NetB-ID", "NetC-ID"]),
    "MY": dict(name="Malaysia", cc="60", prefixes=["11", "12", "13", "16", "19"], tail=7, price=0.030, cost=0.025,
               networks=["NetA-MY", "NetB-MY"]),
    "SG": dict(name="Singapore", cc="65", prefixes=["8", "9"], tail=7, price=0.040, cost=0.034, networks=["NetA-SG"]),
    "TH": dict(name="Thailand", cc="66", prefixes=["81", "82", "89"], tail=7, price=0.050, cost=0.042,
               networks=["NetA-TH"]),
    "LK": dict(name="Sri Lanka", cc="94", prefixes=["71", "72", "75", "77"], tail=7, price=0.090, cost=0.070,
               networks=["NetA-LK"]),
    "CH": dict(name="Switzerland", cc="41", prefixes=["41"], tail=9, price=0.010, cost=0.009, networks=["P2A-Numbers"]),
}


@dataclass
class Conn:
    name: str
    client: str
    traffic_type: str          # A2P (application-to-person) or P2P (person-to-person/application)
    rate: float                # messages per minute (baseline)
    country_mix: dict
    sources: list = field(default_factory=list)
    fail_rate: float = 0.04
    supplier: str = "SupplierNorth"


CONNS = [
    Conn("cn-bankalert-01", "BankAlert", "A2P", 10, {"ID": 1.0}, ["BANKALERT"]),
    Conn("cn-shopverify-01", "ShopVerify", "A2P", 12, {"ID": 0.97, "MY": 0.03}, ["SHOPVRF"]),
    Conn("cn-shopverify-02", "ShopVerify", "A2P", 6, {"ID": 0.97, "MY": 0.03}, ["SHOPVRF"]),
    Conn("cn-socialnet-01", "SocialNet", "A2P", 14, {"ID": 0.85, "MY": 0.05, "SG": 0.05, "TH": 0.05}, ["SocialNet"],
         supplier="SupplierSouth"),
    Conn("cn-ridehail-01", "RideHail", "A2P", 5, {"ID": 1.0}, ["RIDEHAIL"]),
    Conn("cn-streamco-01", "StreamCo", "A2P", 4, {"ID": 0.9, "SG": 0.1}, ["STREAMCO"], supplier="SupplierSouth"),
    Conn("cn-travelhub-01", "TravelHub", "A2P", 3, {"ID": 0.6, "SG": 0.2, "MY": 0.2}, ["TRAVELHUB"]),
    Conn("cn-gamepay-01", "GamePay", "A2P", 4, {"ID": 1.0}, ["GAMEPAY"]),
    # Benign look-alike: many senders -> ~40 application-owned numbers in ONE number block.
    # Looks like pumping to a naive rule; it is not. Rules are scoped to A2P to avoid this false positive.
    Conn("cn-p2p-hub-01", "P2PPartner", "P2P", 10, {"CH": 1.0}, [], fail_rate=0.0),
]
BY_NAME = {c.name: c for c in CONNS}


def _diurnal(t: pd.Timestamp) -> float:
    h = t.hour + t.minute / 60
    return 1 + 0.15 * np.sin(2 * np.pi * (h - 9) / 24)


def _msisdns(rng, code: str, n: int) -> list[str]:
    c = COUNTRIES[code]
    pref = rng.choice(c["prefixes"], size=n)
    tail = rng.integers(0, 10 ** c["tail"], size=n)
    return [f'{c["cc"]}{p}{t:0{c["tail"]}d}' for p, t in zip(pref, tail)]


def _rows(rng, conn: Conn, start, minutes, rate, *, country_mix=None, sources=None, fail_rate=None,
          price_mult=1.0, dest=None) -> pd.DataFrame:
    mins = pd.date_range(start, periods=minutes, freq="min")
    counts = rng.poisson([rate * _diurnal(t) for t in mins])
    n = int(counts.sum())
    if n == 0:
        return pd.DataFrame()
    ts = mins[np.repeat(np.arange(minutes), counts)] + pd.to_timedelta(rng.random(n) * 60, unit="s")
    mix = country_mix or conn.country_mix
    codes = rng.choice(list(mix), size=n, p=list(mix.values()))
    destinations = np.empty(n, dtype=object)
    for code in np.unique(codes):
        idx = np.where(codes == code)[0]
        destinations[idx] = dest(len(idx)) if dest else _msisdns(rng, code, len(idx))
    srcs = sources or conn.sources
    source = rng.choice(srcs, size=n) if srcs else np.array(_msisdns(rng, "ID", n), dtype=object)
    fr = conn.fail_rate if fail_rate is None else fail_rate
    failed = rng.random(n) < fr
    status = np.where(failed, rng.choice(["UNDELIV", "EXPIRED", "REJECTD"], size=n, p=[.6, .3, .1]), "DELIVRD")
    err = np.where(failed, rng.choice(["1001", "1027", "2027", "0062"], size=n), "000")
    price = np.array([COUNTRIES[c]["price"] for c in codes]) * price_mult
    cost = np.array([COUNTRIES[c]["cost"] for c in codes])
    return pd.DataFrame({
        "received_time": ts,
        "source_addr": source,
        "destination_addr": destinations,
        "client_name": conn.client,
        "client_connection_name": conn.name,
        "traffic_type": conn.traffic_type,
        "country": [COUNTRIES[c]["name"] for c in codes],
        "network": [rng.choice(COUNTRIES[c]["networks"]) for c in codes],
        "dlr_status": status,
        "dlr_error_code": err,
        "supplier_name": conn.supplier,
        "price": price.round(5),
        "cost": cost,
        "margin": (price - cost).round(5),
        "time_to_deliver_ms": rng.lognormal(7.0, 0.8, size=n).astype(int),
    })


def _sequential(base: int):
    counter = {"i": 0}

    def gen(n):
        out = [str(base + counter["i"] + k) for k in range(n)]
        counter["i"] += n
        return out
    return gen


def generate(seed: int = 7, hours: int = 6, start: str = "2026-01-05 08:00:00"):
    """Return (cdr_df, ground_truth_df). Deterministic for a given seed."""
    if hours < 6:
        raise ValueError("hours must be >= 6 so the injected scenarios fit")
    rng = np.random.default_rng(seed)
    t0 = pd.Timestamp(start)
    total = hours * 60
    p2p_dest = [str(41415737000 + k) for k in range(40)]

    # Scenarios that REPLACE baseline traffic for a connection during the interval.
    replace = {
        "S3_route_degradation": ("cn-ridehail-01", 280, 15, dict(fail_rate=0.85), ["R003_failure_rate"],
                                 "Route starts failing most deliveries"),
        "S4_financial_anomaly": ("cn-travelhub-01", 210, 15, dict(price_mult=30.0, country_mix={"SG": 1.0}),
                                 ["R005_financial_anomaly"], "Billing price 30x the norm for one destination"),
        "S5_new_destination_country": ("cn-gamepay-01", 300, 15, dict(country_mix={"TH": 1.0}, rate=6),
                                       ["R004_new_destination_country"], "Traffic suddenly goes to a never-seen country"),
    }
    # Scenarios that ADD traffic on top of the baseline.
    additive = {
        "S1_pumping_range": ("cn-shopverify-02", 180, 20, dict(rate=120, country_mix={"LK": 1.0}, fail_rate=0.0,
                             dest=_sequential(94771230000)),
                             ["R001_volume_spike", "R002_sequential_range", "R004_new_destination_country"],
                             "OTP-pumping style burst to a sequential number range in a high-cost country"),
        "S2_new_sender_burst": ("cn-socialnet-01", 250, 10, dict(rate=60, sources=["PROMO-X7"]),
                                ["R006_new_sender_burst"], "Unknown sender ID bursts immediately"),
    }

    frames, truth = [], []
    for conn in CONNS:
        segs, cur = [], 0
        over = sorted((off, dur, kw) for (c, off, dur, kw, *_r) in replace.values() if c == conn.name)
        for off, dur, kw in over:
            if off > cur:
                segs.append((cur, off - cur, {}))
            segs.append((off, dur, kw))
            cur = off + dur
        if cur < total:
            segs.append((cur, total - cur, {}))
        for off, dur, kw in segs:
            kw = dict(kw)
            rate = kw.pop("rate", conn.rate)
            if conn.traffic_type == "P2P":
                kw["dest"] = lambda n: list(rng.choice(p2p_dest, size=n))
            frames.append(_rows(rng, conn, t0 + pd.Timedelta(minutes=off), dur, rate, **kw))
    for sid, (c, off, dur, kw, rules, desc) in additive.items():
        kw = dict(kw)
        rate = kw.pop("rate")
        frames.append(_rows(rng, BY_NAME[c], t0 + pd.Timedelta(minutes=off), dur, rate, **kw))
    for sid, (c, off, dur, kw, rules, desc) in {**replace, **additive}.items():
        truth.append(dict(scenario=sid, connection=c, start=t0 + pd.Timedelta(minutes=off),
                          end=t0 + pd.Timedelta(minutes=off + dur), expected_rules=";".join(rules), description=desc))

    df = pd.concat([f for f in frames if len(f)], ignore_index=True).sort_values("received_time").reset_index(drop=True)
    df.insert(0, "message_id", [f"msg-{i:07d}" for i in range(len(df))])
    return df, pd.DataFrame(truth)
