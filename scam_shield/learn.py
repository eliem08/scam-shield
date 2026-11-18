"""Learn from messages people report, on top of the rules.

A multinomial naive Bayes model over words and word pairs, trained on messages labelled scam or safe (one at a
time with `report`, or in bulk with `learn`). It only ever *adds* risk: a message that reads like reported scams
gets a "learned_pattern" signal; nothing a model learns can talk the rules out of a warning, because a missed
scam costs far more than a false alarm.

Privacy: the model keeps word counts, never the messages. It is stored beside the safe word (SCAM_SHIELD_HOME).
"""

from __future__ import annotations

import itertools
import json
import math
import os
import pathlib
import re

from .core import _normalise

MIN_EACH = 10  # labelled messages of each kind before the model is used
ALPHA = 1.0
URL = re.compile(r"https?://\S+|www\.\S+|\b[\w-]+\.(?:com|net|org|io|co|ly|me|info|xyz|top)\b\S*")
MONEY = re.compile(r"[$£€]\s?\d[\d,.]*|\b\d[\d,.]*\s?(?:usd|dollars|eur|gbp)\b")


def model_path() -> pathlib.Path:
    home = os.environ.get("SCAM_SHIELD_HOME") or str(pathlib.Path.home() / ".scam-shield")
    return pathlib.Path(home) / "model.json"


def tokens(text: str) -> list[str]:
    t = _normalise(text)
    t = URL.sub(" _url_ ", t)
    t = MONEY.sub(" _money_ ", t)
    t = re.sub(r"\d+", " _num_ ", t)
    words = re.findall(r"[a-z_']{2,}", t)
    return words + [f"{a} {b}" for a, b in itertools.pairwise(words)]


class Model:
    def __init__(self, doc: dict | None = None):
        doc = doc or {}
        self.docs = {"scam": 0, "safe": 0, **doc.get("docs", {})}
        self.counts = {
            "scam": dict(doc.get("counts", {}).get("scam", {})),
            "safe": dict(doc.get("counts", {}).get("safe", {})),
        }

    @classmethod
    def load(cls, path: pathlib.Path | None = None) -> Model:
        path = path or model_path()
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except FileNotFoundError:
            return cls()
        if not isinstance(doc, dict) or not isinstance(doc.get("counts"), dict):
            raise ValueError(f"{path}: not a scam-shield model")
        return cls(doc)

    def save(self, path: pathlib.Path | None = None):
        path = path or model_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "docs": self.docs, "counts": self.counts}, fh)
        os.replace(tmp, path)

    def add(self, text: str, label: str):
        if label not in ("scam", "safe"):
            raise ValueError("label must be scam or safe")
        if not text.strip():
            raise ValueError("message is empty")
        self.docs[label] += 1
        c = self.counts[label]
        for tok in tokens(text):
            c[tok] = c.get(tok, 0) + 1

    @property
    def ready(self) -> bool:
        return min(self.docs.values()) >= MIN_EACH

    def _logp(self, tok: str) -> tuple[float, float]:
        vocab = len(set(self.counts["scam"]) | set(self.counts["safe"])) or 1
        out = []
        for label in ("scam", "safe"):
            total = sum(self.counts[label].values())
            out.append(math.log((self.counts[label].get(tok, 0) + ALPHA) / (total + ALPHA * vocab)))
        return out[0], out[1]

    def score(self, text: str) -> tuple[float, list[str]]:
        """(probability the message is a scam, the words that pushed it most towards scam)."""
        n = sum(self.docs.values())
        logodds = math.log((self.docs["scam"] + 1) / (n + 2)) - math.log((self.docs["safe"] + 1) / (n + 2))
        pushes = {}
        for tok in tokens(text):
            s, f = self._logp(tok)
            logodds += s - f
            if tok in self.counts["scam"]:
                pushes[tok] = max(pushes.get(tok, -1e9), s - f)
        logodds = max(-50.0, min(50.0, logodds))
        top = [t for t, v in sorted(pushes.items(), key=lambda kv: -kv[1]) if v > 0][:8]
        return 1 / (1 + math.exp(-logodds)), top


def learned_signal(model: Model, text: str):
    """A (weight, evidence) pair when the model is trained and the message reads like reported scams."""
    if not model.ready:
        return None
    p, top = model.score(text)
    if p < 0.7:
        return None
    shown = [_show(t) for t in top if not set(t.split()) <= FILLER][:3]
    return round(
        40 * (p - 0.5) / 0.5
    ), f"reads like messages reported as scams ({', '.join(shown) or 'overall wording'})"


FILLER = {
    "a",
    "an",
    "the",
    "to",
    "at",
    "of",
    "on",
    "in",
    "is",
    "be",
    "and",
    "or",
    "for",
    "your",
    "you",
    "it",
    "we",
    "our",
}
FILLER |= {"_url_", "_num_", "_money_"}


def _show(tok: str) -> str:
    for raw, words in (("_url_", "a link"), ("_money_", "an amount"), ("_num_", "a number")):
        tok = tok.replace(raw, words)
    return f'"{tok}"'


def load_labelled(path: str) -> list[tuple[str, str]]:
    import csv

    rows = []
    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        cols = {(c or "").strip().lower(): c for c in reader.fieldnames or []}
        text_col = next((cols[c] for c in ("text", "message", "body", "content") if c in cols), None)
        label_col = next((cols[c] for c in ("label", "class", "type", "verdict") if c in cols), None)
        if not text_col or not label_col:
            raise ValueError(f"{path}: needs a text column and a label column (scam/safe)")
        for n, row in enumerate(reader, 2):
            label = (row.get(label_col) or "").strip().lower()
            label = {
                "spam": "scam",
                "fraud": "scam",
                "phishing": "scam",
                "ham": "safe",
                "ok": "safe",
                "legit": "safe",
            }.get(label, label)
            if label not in ("scam", "safe"):
                raise ValueError(f"{path} line {n}: label must be scam or safe, got {row.get(label_col)!r}")
            text = (row.get(text_col) or "").strip()
            if text:
                rows.append((text, label))
    if not rows:
        raise ValueError(f"{path}: no labelled messages")
    return rows


def evaluate(rows: list[tuple[str, str]], folds: int = 5) -> dict:
    """Cross-validated: detection (scams not called safe) and false alarms (safe ones not called safe)."""
    from .core import analyze

    def rates(flagged: list[bool]) -> tuple[float, float]:
        scam = [f for f, (_, lab) in zip(flagged, rows) if lab == "scam"]
        safe = [f for f, (_, lab) in zip(flagged, rows) if lab == "safe"]
        return (sum(scam) / len(scam) if scam else 0.0, sum(safe) / len(safe) if safe else 0.0)

    rules = [analyze(t).label != "safe" for t, _ in rows]
    combined = [False] * len(rows)
    for f in range(folds):
        m = Model()
        for i, (t, lab) in enumerate(rows):
            if i % folds != f:
                m.add(t, lab)
        for i in range(f, len(rows), folds):
            combined[i] = analyze(rows[i][0], model=m).label != "safe"
    (d0, fa0), (d1, fa1) = rates(rules), rates(combined)
    return {
        "messages": len(rows),
        "scams": sum(lab == "scam" for _, lab in rows),
        "rules": {"detection": round(d0, 3), "false_alarms": round(fa0, 3)},
        "rules_and_learning": {"detection": round(d1, 3), "false_alarms": round(fa1, 3)},
    }
