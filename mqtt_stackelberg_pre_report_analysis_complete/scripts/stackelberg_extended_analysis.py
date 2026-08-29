#!/usr/bin/env python3
"""
Extended pre-report analysis for the MQTT Stackelberg security model.

This script completes the analyses that should be finalized before thesis writing:
1) DoS metric-weight sensitivity over (wP, wF, wD)
2) CIA-priority sensitivity
3) Security-floor feasibility analysis
4) Budget-constrained Stackelberg analysis
5) Repeated/adaptive Stackelberg analysis under an exogenous attacker-cost trajectory
6) Publication-oriented summary figures and CSV outputs

The empirical constants are from the frozen ns-3 campaign.

Important scope note:
- Replay and Injection are mapped to Integrity impact.
- DoS is mapped to Availability impact.
- No confidentiality-specific attack was simulated, so confidentiality loss is 0
  in the CIA projection. This is intentional and should be reported as a scope limitation.
"""

from __future__ import annotations

import argparse
import csv
import itertools
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import matplotlib.pyplot as plt
import numpy as np

# ---------------------------------------------------------------------------
# Frozen empirical inputs
# ---------------------------------------------------------------------------

D0_MS = 1.014581

# DoS without rate limiting at lambda_ref = 900 msg/s
PDR_NO_RL = 0.8865
FB_NO_RL = 0.1928
DELAY_NO_RL_MS = 203.24

# DoS with rate limiting at 50 msg/s
PDR_RL = 1.0
FB_RL = 0.0
DELAY_RL_MS = 2.463

# Reference game costs
REF_CR = 0.10
REF_CI = 0.10
REF_CD = 0.10
REF_CRA = 0.10
REF_CIA = 0.10
REF_CLAMBDA = 0.10

EPS = 1e-12

DEFENSES = {
    "d0":   (0, 0, 0),
    "dR":   (1, 0, 0),
    "dI":   (0, 1, 0),
    "dD":   (0, 0, 1),
    "dRI":  (1, 1, 0),
    "dRD":  (1, 0, 1),
    "dID":  (0, 1, 1),
    "dRID": (1, 1, 1),
}

ATTACKS = ("A0", "AR", "AI", "AD")


@dataclass(frozen=True)
class CostScenario:
    cR: float = REF_CR
    cI: float = REF_CI
    cD: float = REF_CD
    cRA: float = REF_CRA
    cIA: float = REF_CIA
    cLambda: float = REF_CLAMBDA


@dataclass(frozen=True)
class DosWeights:
    wP: float
    wF: float
    wD: float


@dataclass(frozen=True)
class CiaWeights:
    wC: float
    wI: float
    wA: float


# ---------------------------------------------------------------------------
# Core impact model
# ---------------------------------------------------------------------------

def normalized_delay(delay_ms: float) -> float:
    delta = max(0.0, (delay_ms - D0_MS) / D0_MS)
    return delta / (1.0 + delta)


D_HAT_NO_RL = normalized_delay(DELAY_NO_RL_MS)
D_HAT_RL = normalized_delay(DELAY_RL_MS)


def dos_severity(weights: DosWeights, rate_limited: bool) -> float:
    if rate_limited:
        pdr, fb, d_hat = PDR_RL, FB_RL, D_HAT_RL
    else:
        pdr, fb, d_hat = PDR_NO_RL, FB_NO_RL, D_HAT_NO_RL

    return (
        weights.wP * (1.0 - pdr)
        + weights.wF * fb
        + weights.wD * d_hat
    )


def base_impact(defense: str, attack: str, dos_weights: DosWeights) -> float:
    xR, xI, xD = DEFENSES[defense]

    if attack == "A0":
        return 0.0
    if attack == "AR":
        return 0.0 if xR else 1.0
    if attack == "AI":
        return 0.0 if xI else 1.0
    if attack == "AD":
        return dos_severity(dos_weights, rate_limited=bool(xD))

    raise ValueError(attack)


def cia_projected_impact(
    defense: str,
    attack: str,
    dos_weights: DosWeights,
    cia: CiaWeights,
) -> float:
    """
    CIA projection:
      AR, AI -> Integrity
      AD     -> Availability
      Confidentiality -> no direct simulated loss in current attack set
    """
    phi = base_impact(defense, attack, dos_weights)

    if attack == "A0":
        return 0.0
    if attack in ("AR", "AI"):
        return cia.wI * phi
    if attack == "AD":
        return cia.wA * phi

    raise ValueError(attack)


def defense_cost(defense: str, s: CostScenario) -> float:
    xR, xI, xD = DEFENSES[defense]
    return xR * s.cR + xI * s.cI + xD * s.cD


def attack_cost(attack: str, s: CostScenario) -> float:
    if attack == "A0":
        return 0.0
    if attack == "AR":
        return s.cRA
    if attack == "AI":
        return s.cIA
    if attack == "AD":
        return s.cLambda
    raise ValueError(attack)


def attacker_utility(
    defense: str,
    attack: str,
    costs: CostScenario,
    dos_weights: DosWeights,
    cia: CiaWeights | None = None,
) -> float:
    if cia is None:
        phi = base_impact(defense, attack, dos_weights)
    else:
        phi = cia_projected_impact(defense, attack, dos_weights, cia)
    return phi - attack_cost(attack, costs)


def defender_utility(
    defense: str,
    attack: str,
    costs: CostScenario,
    dos_weights: DosWeights,
    cia: CiaWeights | None = None,
) -> float:
    if cia is None:
        phi = base_impact(defense, attack, dos_weights)
    else:
        phi = cia_projected_impact(defense, attack, dos_weights, cia)
    return -phi - defense_cost(defense, costs)


def argmax_ties(values: Dict[str, float]) -> Tuple[List[str], float]:
    m = max(values.values())
    return [k for k, v in values.items() if abs(v - m) <= EPS], m


def solve_stackelberg(
    costs: CostScenario,
    dos_weights: DosWeights,
    cia: CiaWeights | None = None,
    feasible_defenses: List[str] | None = None,
    tie_break: str = "strong",
) -> Dict[str, object]:
    """
    Pure-strategy Stackelberg solution with explicit follower tie handling.
    """
    if feasible_defenses is None:
        feasible_defenses = list(DEFENSES)

    leader_values: Dict[str, float] = {}
    chosen_attack: Dict[str, str] = {}
    attacker_br_sets: Dict[str, List[str]] = {}

    for d in feasible_defenses:
        au = {
            a: attacker_utility(d, a, costs, dos_weights, cia)
            for a in ATTACKS
        }
        br, _ = argmax_ties(au)
        attacker_br_sets[d] = br

        du = {
            a: defender_utility(d, a, costs, dos_weights, cia)
            for a in br
        }

        if tie_break == "strong":
            a_star = max(br, key=lambda a: (du[a], a))
        elif tie_break == "weak":
            a_star = min(br, key=lambda a: (du[a], a))
        else:
            raise ValueError("tie_break must be strong or weak")

        chosen_attack[d] = a_star
        leader_values[d] = du[a_star]

    d_star, value = argmax_ties(leader_values)
    pairs = [(d, chosen_attack[d]) for d in d_star]

    return {
        "equilibrium_pairs": pairs,
        "defender_value": value,
        "defender_values": leader_values,
        "attacker_br_sets": attacker_br_sets,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def simplex_grid(step: float) -> List[Tuple[float, float, float]]:
    n = round(1.0 / step)
    values = []
    for i in range(n + 1):
        for j in range(n + 1 - i):
            k = n - i - j
            values.append((i / n, j / n, k / n))
    return values


def write_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def pair_string(result: Dict[str, object]) -> str:
    return "|".join(f"{d}:{a}" for d, a in result["equilibrium_pairs"])


# ---------------------------------------------------------------------------
# 1) DoS metric-weight sensitivity
# ---------------------------------------------------------------------------

def run_dos_weight_sensitivity(out_dir: Path, tie_break: str) -> List[Dict[str, object]]:
    costs = CostScenario()
    rows = []

    for wP, wF, wD in simplex_grid(0.05):
        w = DosWeights(wP, wF, wD)
        result = solve_stackelberg(costs, w, tie_break=tie_break)
        rows.append({
            "wP": wP,
            "wF": wF,
            "wD": wD,
            "S_no_RL": dos_severity(w, False),
            "S_RL": dos_severity(w, True),
            "equilibrium_pairs": pair_string(result),
            "defender_value": result["defender_value"],
        })

    write_csv(out_dir / "dos_weight_sensitivity.csv", rows)
    return rows


# ---------------------------------------------------------------------------
# 2) CIA-priority sensitivity
# ---------------------------------------------------------------------------

def run_cia_sensitivity(out_dir: Path, tie_break: str) -> List[Dict[str, object]]:
    costs = CostScenario()
    dos_w = DosWeights(1/3, 1/3, 1/3)
    rows = []

    for wC, wI, wA in simplex_grid(0.05):
        cia = CiaWeights(wC, wI, wA)
        result = solve_stackelberg(costs, dos_w, cia=cia, tie_break=tie_break)
        rows.append({
            "wC": wC,
            "wI": wI,
            "wA": wA,
            "equilibrium_pairs": pair_string(result),
            "defender_value": result["defender_value"],
        })

    write_csv(out_dir / "cia_weight_sensitivity.csv", rows)
    return rows


# ---------------------------------------------------------------------------
# 3) Security-floor analysis
# ---------------------------------------------------------------------------

def security_score(defense: str, dos_weights: DosWeights) -> float:
    """
    Worst-case residual security:
        Q(d) = 1 - max_{a in {AR,AI,AD}} Phi(d,a)
    """
    worst_impact = max(base_impact(defense, a, dos_weights) for a in ("AR", "AI", "AD"))
    return 1.0 - worst_impact


def run_security_floor(out_dir: Path, tie_break: str) -> List[Dict[str, object]]:
    costs = CostScenario()
    dos_w = DosWeights(1/3, 1/3, 1/3)
    rows = []

    floors = [round(x, 2) for x in np.arange(0.0, 1.0001, 0.05)]

    for floor in floors:
        feasible = [
            d for d in DEFENSES
            if security_score(d, dos_w) + EPS >= floor
        ]

        if feasible:
            result = solve_stackelberg(
                costs, dos_w,
                feasible_defenses=feasible,
                tie_break=tie_break,
            )
            eq = pair_string(result)
            value = result["defender_value"]
        else:
            eq = "INFEASIBLE"
            value = ""

        rows.append({
            "security_floor": floor,
            "feasible_defenses": "|".join(feasible),
            "equilibrium_pairs": eq,
            "defender_value": value,
        })

    write_csv(out_dir / "security_floor_analysis.csv", rows)
    return rows


# ---------------------------------------------------------------------------
# 4) Budget-constrained analysis
# ---------------------------------------------------------------------------

def run_budget_analysis(out_dir: Path, tie_break: str) -> List[Dict[str, object]]:
    costs = CostScenario()
    dos_w = DosWeights(1/3, 1/3, 1/3)
    rows = []

    budgets = [round(x, 2) for x in np.arange(0.0, 0.5001, 0.01)]

    for budget in budgets:
        feasible = [
            d for d in DEFENSES
            if defense_cost(d, costs) <= budget + EPS
        ]
        result = solve_stackelberg(
            costs, dos_w,
            feasible_defenses=feasible,
            tie_break=tie_break,
        )
        rows.append({
            "budget": budget,
            "feasible_defenses": "|".join(feasible),
            "equilibrium_pairs": pair_string(result),
            "defender_value": result["defender_value"],
        })

    write_csv(out_dir / "budget_analysis.csv", rows)
    return rows


# ---------------------------------------------------------------------------
# 5) Repeated/adaptive Stackelberg analysis
# ---------------------------------------------------------------------------

def run_adaptive_analysis(out_dir: Path, tie_break: str) -> List[Dict[str, object]]:
    """
    Repeated one-shot Stackelberg game with exogenous DoS-cost variation.

    The trajectory is intentionally a deterministic up/down sweep, not claimed
    as empirical temporal behavior. Its purpose is to show whether the optimal
    defense adapts when the attacker's DoS cost crosses equilibrium thresholds.
    """
    dos_w = DosWeights(1/3, 1/3, 1/3)

    trajectory = (
        [round(x, 2) for x in np.arange(0.00, 0.3101, 0.02)]
        + [round(x, 2) for x in np.arange(0.28, -0.0001, -0.02)]
    )

    rows = []

    for round_idx, c_lambda in enumerate(trajectory, start=1):
        costs = CostScenario(cLambda=c_lambda)
        result = solve_stackelberg(costs, dos_w, tie_break=tie_break)
        rows.append({
            "round": round_idx,
            "cLambda": c_lambda,
            "equilibrium_pairs": pair_string(result),
            "defender_value": result["defender_value"],
        })

    write_csv(out_dir / "adaptive_repeated_analysis.csv", rows)
    return rows


# ---------------------------------------------------------------------------
# Visualization
# ---------------------------------------------------------------------------

def plot_category_counts(rows: List[Dict[str, object]], key: str, title: str, path: Path) -> None:
    counts = Counter(str(r[key]) for r in rows)
    items = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)

    labels = [k for k, _ in items]
    vals = [v for _, v in items]

    fig, ax = plt.subplots(figsize=(9, max(4.5, 0.45 * len(items) + 1.5)))
    y = np.arange(len(items))
    ax.barh(y, vals)
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlabel("Number of parameter combinations")
    ax.set_title(title)

    for i, v in enumerate(vals):
        ax.text(v, i, f" {v}", va="center", fontsize=8)

    fig.tight_layout()
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_simplex_scatter(
    rows: List[Dict[str, object]],
    a_key: str,
    b_key: str,
    c_key: str,
    label_key: str,
    title: str,
    path: Path,
) -> None:
    """
    Ternary/simplex projection using barycentric-to-Cartesian coordinates.
    No external ternary plotting package required.
    """
    labels = sorted({str(r[label_key]) for r in rows})

    grouped = {lab: ([], []) for lab in labels}
    for r in rows:
        a, b, c = float(r[a_key]), float(r[b_key]), float(r[c_key])
        # Triangle vertices: a=(0,0), b=(1,0), c=(0.5,sqrt(3)/2)
        x = b + 0.5 * c
        y = (np.sqrt(3) / 2.0) * c
        lab = str(r[label_key])
        grouped[lab][0].append(x)
        grouped[lab][1].append(y)

    fig, ax = plt.subplots(figsize=(8, 7))
    for lab in labels:
        xs, ys = grouped[lab]
        ax.scatter(xs, ys, s=30, label=lab)

    triangle_x = [0, 1, 0.5, 0]
    triangle_y = [0, 0, np.sqrt(3)/2, 0]
    ax.plot(triangle_x, triangle_y, linewidth=1)

    ax.text(-0.03, -0.035, a_key, ha="right", va="top")
    ax.text(1.03, -0.035, b_key, ha="left", va="top")
    ax.text(0.5, np.sqrt(3)/2 + 0.035, c_key, ha="center", va="bottom")

    ax.set_title(title)
    ax.set_aspect("equal")
    ax.set_axis_off()
    ax.legend(title="Equilibrium", loc="best", fontsize=8)

    fig.tight_layout()
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_floor(rows: List[Dict[str, object]], path: Path) -> None:
    floors = [float(r["security_floor"]) for r in rows]
    feasible_count = [
        0 if not r["feasible_defenses"] else len(str(r["feasible_defenses"]).split("|"))
        for r in rows
    ]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.step(floors, feasible_count, where="post")
    ax.set_xlabel("Security floor")
    ax.set_ylabel("Number of feasible defense strategies")
    ax.set_title("Security-floor feasibility")
    fig.tight_layout()
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_budget(rows: List[Dict[str, object]], path: Path) -> None:
    budgets = [float(r["budget"]) for r in rows]
    values = [float(r["defender_value"]) for r in rows]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(budgets, values, marker="o", markersize=2)
    ax.set_xlabel("Defense budget")
    ax.set_ylabel("Optimal defender Stackelberg value")
    ax.set_title("Budget-constrained defense performance")
    fig.tight_layout()
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_adaptive(rows: List[Dict[str, object]], path: Path) -> None:
    rounds = [int(r["round"]) for r in rows]
    c_lambda = [float(r["cLambda"]) for r in rows]
    values = [float(r["defender_value"]) for r in rows]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(rounds, c_lambda, marker="o", markersize=3, label="DoS attack cost")
    ax.plot(rounds, values, marker="s", markersize=3, label="Defender value")
    ax.set_xlabel("Repeated-game round")
    ax.set_ylabel("Normalized value")
    ax.set_title("Adaptive repeated Stackelberg response")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def write_key_findings(
    out_dir: Path,
    dos_rows: List[Dict[str, object]],
    cia_rows: List[Dict[str, object]],
    floor_rows: List[Dict[str, object]],
    budget_rows: List[Dict[str, object]],
    adaptive_rows: List[Dict[str, object]],
) -> None:
    lines = []

    lines.append("FROZEN EMPIRICAL CONSTANTS")
    lines.append(f"D0_ms={D0_MS:.6f}")
    lines.append(f"D_hat_no_RL={D_HAT_NO_RL:.6f}")
    lines.append(f"D_hat_RL={D_HAT_RL:.6f}")
    lines.append("")

    for name, rows in [
        ("DoS-weight sensitivity", dos_rows),
        ("CIA sensitivity", cia_rows),
        ("Adaptive repeated analysis", adaptive_rows),
    ]:
        counts = Counter(str(r["equilibrium_pairs"]) for r in rows)
        lines.append(name)
        for eq, count in counts.most_common():
            lines.append(f"  {eq}: {count}")
        lines.append("")

    # Security floors where feasibility changes
    prev = None
    lines.append("Security-floor feasibility changes")
    for r in floor_rows:
        cur = r["feasible_defenses"]
        if cur != prev:
            lines.append(
                f"  floor={r['security_floor']}: feasible={cur or 'NONE'}, "
                f"eq={r['equilibrium_pairs']}"
            )
            prev = cur
    lines.append("")

    # Budget equilibrium transitions
    prev = None
    lines.append("Budget equilibrium transitions")
    for r in budget_rows:
        cur = r["equilibrium_pairs"]
        if cur != prev:
            lines.append(
                f"  budget={r['budget']}: eq={cur}, "
                f"value={r['defender_value']}"
            )
            prev = cur

    (out_dir / "key_findings.txt").write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default="stackelberg_extended_analysis")
    parser.add_argument("--tie-break", choices=["strong", "weak"], default="strong")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    figures_dir = out_dir / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    dos_rows = run_dos_weight_sensitivity(out_dir, args.tie_break)
    cia_rows = run_cia_sensitivity(out_dir, args.tie_break)
    floor_rows = run_security_floor(out_dir, args.tie_break)
    budget_rows = run_budget_analysis(out_dir, args.tie_break)
    adaptive_rows = run_adaptive_analysis(out_dir, args.tie_break)

    plot_category_counts(
        dos_rows, "equilibrium_pairs",
        "Equilibrium distribution over DoS metric weights",
        figures_dir / "dos_weight_equilibrium_counts.png",
    )
    plot_simplex_scatter(
        dos_rows, "wP", "wF", "wD", "equilibrium_pairs",
        "DoS metric-weight sensitivity on the simplex",
        figures_dir / "dos_weight_simplex.png",
    )

    plot_category_counts(
        cia_rows, "equilibrium_pairs",
        "Equilibrium distribution over CIA priorities",
        figures_dir / "cia_equilibrium_counts.png",
    )
    plot_simplex_scatter(
        cia_rows, "wC", "wI", "wA", "equilibrium_pairs",
        "CIA-priority sensitivity on the simplex",
        figures_dir / "cia_simplex.png",
    )

    plot_floor(floor_rows, figures_dir / "security_floor_feasibility.png")
    plot_budget(budget_rows, figures_dir / "budget_defender_value.png")
    plot_adaptive(adaptive_rows, figures_dir / "adaptive_repeated_response.png")

    write_key_findings(
        out_dir,
        dos_rows, cia_rows, floor_rows, budget_rows, adaptive_rows
    )

    print("Extended analysis complete.")
    print(f"D_hat_no_RL = {D_HAT_NO_RL:.6f}")
    print(f"D_hat_RL    = {D_HAT_RL:.6f}")
    print(f"Output dir  = {out_dir.resolve()}")
    print(f"DoS weight rows = {len(dos_rows)}")
    print(f"CIA rows        = {len(cia_rows)}")
    print(f"Floor rows      = {len(floor_rows)}")
    print(f"Budget rows     = {len(budget_rows)}")
    print(f"Adaptive rounds = {len(adaptive_rows)}")


if __name__ == "__main__":
    main()
