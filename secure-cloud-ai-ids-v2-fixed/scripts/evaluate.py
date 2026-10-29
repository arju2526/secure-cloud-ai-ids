"""Evaluation of rules / ML-v1 (original) / ML-v2 (retrained) / hybrids on held-out labelled synthetic flows.

Run from backend/:  python3 ../scripts/evaluate.py
Test seeds 101-105 are disjoint from training (11) and threshold-calibration (22) seeds.
"""
import json, os, sys, platform
from types import SimpleNamespace
import numpy as np, joblib, sklearn
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from sklearn.metrics import roc_auc_score
from app.ml.dataset import generate, LABELS
from app.ml.features import feature_matrix
from app.ml import train as t
from app.services.rule_engine import evaluate_network_rules
import app.ml.legacy as legacy_pkg

OUT = os.path.join(os.path.dirname(__file__), "..", "docs", "results")
os.makedirs(OUT, exist_ok=True)
SEEDS = [101, 102, 103, 104, 105]
N_BENIGN, N_ATTACK = 4000, 500

v2m, v2s = joblib.load(t.MODEL_PATH), joblib.load(t.SCALER_PATH)
thr = json.load(open(t.META_PATH))["threshold"]
ldir = os.path.dirname(legacy_pkg.__file__)
v1m, v1s = joblib.load(os.path.join(ldir, "isolation_forest.joblib")), joblib.load(os.path.join(ldir, "scaler.joblib"))


def rules_pred(recs):
    return np.array([len(evaluate_network_rules(SimpleNamespace(**r))) > 0 for r in recs])


def v1_pred(recs):
    X = v1s.transform(np.array([[r["bytes_sent"], r["bytes_received"], r["packet_count"], r["dst_port"]] for r in recs], dtype=float))
    sc = -v1m.score_samples(X)
    return (v1m.predict(X) == -1) | (sc > 0.65), sc


def v2_pred(recs):
    sc = -v2m.score_samples(v2s.transform(feature_matrix(recs)))
    return sc > thr, sc


def metrics(y, p):
    tp = int((y & p).sum()); fp = int((~y & p).sum()); fn = int((y & ~p).sum()); tn = int((~y & ~p).sum())
    P = tp / (tp + fp) if tp + fp else 0.0; R = tp / (tp + fn) if tp + fn else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, accuracy=(tp + tn) / len(y), precision=P, recall=R,
                f1=2 * P * R / (P + R) if P + R else 0.0, fpr=fp / (fp + tn))


systems = ["Rules only", "ML v1 (original)", "ML v2 (retrained)", "Hybrid (Rules + ML v1)", "Hybrid (Rules + ML v2)"]
per_seed = {s: [] for s in systems}; perclass = {s: {c: [] for c in LABELS[1:]} for s in systems}
stealth_rec = {s: [] for s in systems}; auc = {"ML v1 (original)": [], "ML v2 (retrained)": []}
benign_ports = {s: {} for s in systems}
conf = {s: np.zeros((2, 2), int) for s in systems}
for seed in SEEDS:
    recs = generate(N_BENIGN, N_ATTACK, seed)
    lab = np.array([r["label"] for r in recs]); y = lab != "benign"; stealth = np.array([r["stealth"] for r in recs])
    rp = rules_pred(recs); p1, s1 = v1_pred(recs); p2, s2 = v2_pred(recs)
    preds = {systems[0]: rp, systems[1]: p1, systems[2]: p2, systems[3]: rp | p1, systems[4]: rp | p2}
    auc["ML v1 (original)"].append(roc_auc_score(y, s1)); auc["ML v2 (retrained)"].append(roc_auc_score(y, s2))
    for s, p in preds.items():
        per_seed[s].append(metrics(y, p))
        for c in LABELS[1:]:
            perclass[s][c].append(float(p[lab == c].mean()))
        stealth_rec[s].append(float(p[y & stealth].mean()))
        m = metrics(y, p); conf[s] += np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]])
        if seed == SEEDS[0]:
            for r, pr in zip(recs, p):
                if r["label"] == "benign" and pr:
                    benign_ports[s][r["dst_port"]] = benign_ports[s].get(r["dst_port"], 0) + 1

agg = {}
for s in systems:
    agg[s] = {k: (float(np.mean([m[k] for m in per_seed[s]])), float(np.std([m[k] for m in per_seed[s]]))) for k in ["accuracy", "precision", "recall", "f1", "fpr"]}
    agg[s]["per_class_recall"] = {c: float(np.mean(v)) for c, v in perclass[s].items()}
    agg[s]["stealth_recall"] = float(np.mean(stealth_rec[s]))
    agg[s]["confusion_sum_over_seeds"] = conf[s].tolist()
    agg[s]["benign_fp_ports_seed101"] = {str(k): v for k, v in sorted(benign_ports[s].items(), key=lambda kv: -kv[1])[:6]}
env = dict(python=platform.python_version(), sklearn=sklearn.__version__, numpy=np.__version__, os=platform.platform(),
           cpu_count=os.cpu_count(), seeds=SEEDS, n_benign_per_seed=N_BENIGN, n_per_attack_class=N_ATTACK,
           v2_threshold=thr, auc={k: [float(np.mean(v)), float(np.std(v))] for k, v in auc.items()})
json.dump(dict(environment=env, results=agg), open(os.path.join(OUT, "evaluation_results.json"), "w"), indent=2)

lines = ["| System | Accuracy | Precision | Recall | F1 | FPR |", "|---|---|---|---|---|---|"]
for s in systems:
    a = agg[s]; lines.append(f"| {s} | " + " | ".join(f"{a[k][0]:.3f} ± {a[k][1]:.3f}" for k in ["accuracy", "precision", "recall", "f1", "fpr"]) + " |")
lines += ["", "| System | " + " | ".join(LABELS[1:]) + " | Stealth-only recall |", "|---|" + "---|" * 5]
for s in systems:
    lines.append(f"| {s} | " + " | ".join(f"{agg[s]['per_class_recall'][c]:.3f}" for c in LABELS[1:]) + f" | {agg[s]['stealth_recall']:.3f} |")
lines += ["", f"ROC-AUC (ML score, malicious vs benign): v1 = {env['auc']['ML v1 (original)'][0]:.3f} ± {env['auc']['ML v1 (original)'][1]:.3f}; v2 = {env['auc']['ML v2 (retrained)'][0]:.3f} ± {env['auc']['ML v2 (retrained)'][1]:.3f}"]
open(os.path.join(OUT, "evaluation_tables.md"), "w").write("\n".join(lines))
print("\n".join(lines)); print(json.dumps(env, indent=1))
for s in systems: print(s, "FP ports:", agg[s]["benign_fp_ports_seed101"])

import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
fig, ax = plt.subplots(1, 5, figsize=(17, 3.4))
for a, s in zip(ax, systems):
    c = conf[s]; a.imshow(c, cmap="Blues")
    for i in range(2):
        for j in range(2): a.text(j, i, c[i, j], ha="center", va="center", color="black", fontsize=10)
    a.set_xticks([0, 1], ["Pred benign", "Pred attack"], fontsize=7); a.set_yticks([0, 1], ["True benign", "True attack"], fontsize=7); a.set_title(s, fontsize=8)
plt.tight_layout(); plt.savefig(os.path.join(OUT, "confusion_matrices.png"), dpi=140); plt.close()
fig, ax = plt.subplots(figsize=(8, 4)); w = 0.16
for i, s in enumerate(systems):
    ax.bar(np.arange(4) + i * w, [agg[s]["per_class_recall"][c] for c in LABELS[1:]], w, label=s)
ax.set_xticks(np.arange(4) + 2 * w, LABELS[1:]); ax.set_ylabel("Detection rate (recall)"); ax.set_ylim(0, 1.05); ax.legend(fontsize=7); ax.set_title("Per-attack-class detection rate (mean of 5 seeds)")
plt.tight_layout(); plt.savefig(os.path.join(OUT, "per_class_recall.png"), dpi=140)
