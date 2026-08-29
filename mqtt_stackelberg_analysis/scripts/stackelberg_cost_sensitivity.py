#!/usr/bin/env python3
"""
Stackelberg cost-sensitivity analysis for the MQTT security game.

Frozen empirical impact values:
    Replay / Injection impact: 0 or 1 according to the enabled defense.
    DoS impact without rate limiting: 0.43377
    DoS impact with rate limiting:    0.19602

Game-layer attacker actions:
    A0 = no attack
    AR = replay
    AI = injection
    AD = DoS

Defender strategies:
    d0, dR, dI, dD, dRI, dRD, dID, dRID

Outputs:
    experiment_A_defender_costs.csv
    experiment_B_attacker_costs.csv
    experiment_C_joint_costs.csv
    equilibrium_summary.csv
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

# ---------------- Frozen impact model ----------------

DOS_NO_RL = 0.43377
DOS_WITH_RL = 0.19602

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

EPS = 1e-12


@dataclass(frozen=True)
class CostScenario:
    cR: float
    cI: float
    cD: float
    cRA: float
    cIA: float
    cLambda: float


def impact(defense: str, attack: str) -> float:
    """Return Phi(d,a) for the frozen reference impact matrix."""
    xR, xI, xD = DEFENSES[defense]

    if attack == "A0":
        return 0.0
    if attack == "AR":
        return 0.0 if xR else 1.0
    if attack == "AI":
        return 0.0 if xI else 1.0
    if attack == "AD":
        return DOS_WITH_RL if xD else DOS_NO_RL

    raise ValueError(f"Unknown attack: {attack}")


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
        # lambda_realized / lambda_ref is approximately 1 at the calibrated point
        return s.cLambda
    raise ValueError(f"Unknown attack: {attack}")


def attacker_utility(defense: str, attack: str, s: CostScenario) -> float:
    return impact(defense, attack) - attack_cost(attack, s)


def defender_utility(defense: str, attack: str, s: CostScenario) -> float:
    return -impact(defense, attack) - defense_cost(defense, s)


def argmax_with_ties(items: Dict[str, float]) -> Tuple[List[str], float]:
    max_value = max(items.values())
    winners = [k for k, v in items.items() if abs(v - max_value) <= EPS]
    return winners, max_value


def attacker_best_response(defense: str, s: CostScenario) -> Tuple[List[str], float, Dict[str, float]]:
    utilities = {a: attacker_utility(defense, a, s) for a in ATTACKS}
    winners, value = argmax_with_ties(utilities)
    return winners, value, utilities


def stackelberg_equilibrium(s: CostScenario, tie_break: str = "strong") -> Dict[str, object]:
    """
    Solve the pure-strategy Stackelberg game.

    tie_break:
      strong = if the follower is indifferent, choose the attack maximizing defender utility.
      weak   = if the follower is indifferent, choose the attack minimizing defender utility.

    This explicitly resolves follower ties rather than silently selecting one action.
    """
    defender_values = {}
    chosen_attacks = {}
    br_sets = {}

    for d in DEFENSES:
        br, _, _ = attacker_best_response(d, s)
        br_sets[d] = br

        du_by_attack = {a: defender_utility(d, a, s) for a in br}

        if tie_break == "strong":
            a_star = max(br, key=lambda a: (du_by_attack[a], a))
        elif tie_break == "weak":
            a_star = min(br, key=lambda a: (du_by_attack[a], a))
        else:
            raise ValueError("tie_break must be 'strong' or 'weak'")

        chosen_attacks[d] = a_star
        defender_values[d] = du_by_attack[a_star]

    d_winners, d_value = argmax_with_ties(defender_values)

    # If multiple defender strategies tie, preserve all of them.
    equilibrium_pairs = [(d, chosen_attacks[d]) for d in d_winners]

    return {
        "defender_best_responses": d_winners,
        "equilibrium_pairs": equilibrium_pairs,
        "defender_value": d_value,
        "attacker_br_sets": br_sets,
        "chosen_attacks": chosen_attacks,
        "defender_values": defender_values,
    }


def frange(start: float, stop: float, step: float) -> List[float]:
    vals = []
    x = start
    while x <= stop + EPS:
        vals.append(round(x, 10))
        x += step
    return vals


def common_row(s: CostScenario, result: Dict[str, object], experiment: str) -> Dict[str, object]:
    pairs = result["equilibrium_pairs"]
    return {
        "experiment": experiment,
        "cR": s.cR,
        "cI": s.cI,
        "cD": s.cD,
        "cRA": s.cRA,
        "cIA": s.cIA,
        "cLambda": s.cLambda,
        "equilibrium_defenses": "|".join(d for d, _ in pairs),
        "equilibrium_attacks": "|".join(a for _, a in pairs),
        "equilibrium_pairs": "|".join(f"{d}:{a}" for d, a in pairs),
        "defender_value": result["defender_value"],
    }


def write_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def experiment_a(out_dir: Path, tie_break: str) -> List[Dict[str, object]]:
    """
    Defender-cost sensitivity:
      cR, cI, cD in [0, 0.50] step 0.05
      attacker costs fixed at 0.10
    """
    grid = frange(0.0, 0.50, 0.05)
    rows = []

    for cR, cI, cD in itertools.product(grid, repeat=3):
        s = CostScenario(cR, cI, cD, 0.10, 0.10, 0.10)
        result = stackelberg_equilibrium(s, tie_break)
        rows.append(common_row(s, result, "A_defender_costs"))

    write_csv(out_dir / "experiment_A_defender_costs.csv", rows)
    return rows


def experiment_b(out_dir: Path, tie_break: str) -> List[Dict[str, object]]:
    """
    Attacker-cost sensitivity:
      cRA, cIA, cLambda in [0, 1.00] step 0.05
      defender costs fixed at 0.10
    """
    grid = frange(0.0, 1.00, 0.05)
    rows = []

    for cRA, cIA, cLambda in itertools.product(grid, repeat=3):
        s = CostScenario(0.10, 0.10, 0.10, cRA, cIA, cLambda)
        result = stackelberg_equilibrium(s, tie_break)
        rows.append(common_row(s, result, "B_attacker_costs"))

    write_csv(out_dir / "experiment_B_attacker_costs.csv", rows)
    return rows


def experiment_c(out_dir: Path, tie_break: str) -> List[Dict[str, object]]:
    """
    Joint sensitivity around the two most important transitions:
      cD around the RL critical region
      cLambda around the DoS deterrence region

    cR = cI = cRA = cIA = 0.10
    """
    cD_grid = frange(0.10, 0.35, 0.01)
    cLambda_grid = frange(0.10, 0.30, 0.01)
    rows = []

    for cD, cLambda in itertools.product(cD_grid, cLambda_grid):
        s = CostScenario(
            cR=0.10,
            cI=0.10,
            cD=cD,
            cRA=0.10,
            cIA=0.10,
            cLambda=cLambda,
        )
        result = stackelberg_equilibrium(s, tie_break)
        rows.append(common_row(s, result, "C_joint_cD_cLambda"))

    write_csv(out_dir / "experiment_C_joint_costs.csv", rows)
    return rows


def summarize(rows: List[Dict[str, object]], out_dir: Path) -> None:
    counts: Dict[Tuple[str, str], int] = {}

    for row in rows:
        key = (str(row["experiment"]), str(row["equilibrium_pairs"]))
        counts[key] = counts.get(key, 0) + 1

    summary_rows = [
        {
            "experiment": exp,
            "equilibrium_pairs": eq,
            "count": count,
        }
        for (exp, eq), count in sorted(counts.items())
    ]

    write_csv(out_dir / "equilibrium_summary.csv", summary_rows)


def print_reference_result(tie_break: str) -> None:
    s = CostScenario(
        cR=0.10, cI=0.10, cD=0.10,
        cRA=0.10, cIA=0.10, cLambda=0.10
    )
    result = stackelberg_equilibrium(s, tie_break)

    print("Reference scenario")
    print("------------------")
    print(f"tie_break = {tie_break}")
    print(f"costs     = {s}")
    print(f"equilibrium pairs = {result['equilibrium_pairs']}")
    print(f"defender value    = {result['defender_value']:.6f}")
    print()

    print("Attacker best responses by defense:")
    for d in DEFENSES:
        br, _, utilities = attacker_best_response(d, s)
        u_str = ", ".join(f"{a}={utilities[a]:.5f}" for a in ATTACKS)
        print(f"  {d:4s}: BR={br} | {u_str}")



# ---------------- Visualization ----------------

def _safe_label(label: str) -> str:
    """Make equilibrium labels easier to read in figures."""
    return label.replace("|", "\n")


def plot_reference_defender_values(out_dir: Path, tie_break: str) -> None:
    """Plot defender Stackelberg values for the reference cost scenario."""
    s = CostScenario(
        cR=0.10, cI=0.10, cD=0.10,
        cRA=0.10, cIA=0.10, cLambda=0.10
    )
    result = stackelberg_equilibrium(s, tie_break)

    names = list(DEFENSES.keys())
    values = [result["defender_values"][d] for d in names]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(names, values)
    ax.set_xlabel("Defense strategy")
    ax.set_ylabel("Defender Stackelberg value")
    ax.set_title("Reference scenario: defender value by strategy")
    ax.axhline(0, linewidth=0.8)
    fig.tight_layout()
    fig.savefig(out_dir / "reference_defender_values.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_equilibrium_counts(
    rows: List[Dict[str, object]],
    out_path: Path,
    title: str,
) -> None:
    """Plot how often each equilibrium pair appears in a sensitivity experiment."""
    counts = Counter(str(row["equilibrium_pairs"]) for row in rows)
    items = sorted(counts.items(), key=lambda x: x[1], reverse=True)

    labels = [_safe_label(k) for k, _ in items]
    values = [v for _, v in items]

    height = max(5, 0.38 * len(items) + 1.5)
    fig, ax = plt.subplots(figsize=(10, height))
    y = np.arange(len(labels))
    ax.barh(y, values)
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlabel("Number of parameter combinations")
    ax.set_ylabel("Stackelberg equilibrium")
    ax.set_title(title)

    for i, value in enumerate(values):
        ax.text(value, i, f" {value}", va="center", fontsize=8)

    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_experiment_c_phase_map(
    rows: List[Dict[str, object]],
    out_path: Path,
) -> None:
    """
    Plot the equilibrium phase map over cD and cLambda.

    Each unique equilibrium pair is mapped to an integer category.  The mapping
    is written directly into the legend, so the plot remains interpretable
    without assuming an ordering among equilibria.
    """
    cD_values = sorted({float(r["cD"]) for r in rows})
    cL_values = sorted({float(r["cLambda"]) for r in rows})
    equilibria = sorted({str(r["equilibrium_pairs"]) for r in rows})

    eq_to_code = {eq: i for i, eq in enumerate(equilibria)}
    grid = np.full((len(cL_values), len(cD_values)), np.nan)

    cD_index = {v: i for i, v in enumerate(cD_values)}
    cL_index = {v: i for i, v in enumerate(cL_values)}

    for row in rows:
        x = cD_index[float(row["cD"])]
        y = cL_index[float(row["cLambda"])]
        grid[y, x] = eq_to_code[str(row["equilibrium_pairs"])]

    fig, ax = plt.subplots(figsize=(9, 6))
    image = ax.imshow(
        grid,
        origin="lower",
        aspect="auto",
        extent=[
            min(cD_values),
            max(cD_values),
            min(cL_values),
            max(cL_values),
        ],
        interpolation="nearest",
    )

    ax.set_xlabel(r"Rate-limiting defense cost $c_D$")
    ax.set_ylabel(r"DoS attack cost $c_\lambda$")
    ax.set_title(r"Joint cost sensitivity: equilibrium phase map")

    # Use a discrete colorbar with equilibrium labels.
    ticks = list(range(len(equilibria)))
    cbar = fig.colorbar(image, ax=ax, ticks=ticks)
    cbar.ax.set_yticklabels(equilibria)
    cbar.set_label("Equilibrium pair")

    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_experiment_a_phase_slices(
    rows: List[Dict[str, object]],
    out_dir: Path,
) -> None:
    """
    Plot two-dimensional defender-cost phase maps for selected cD slices.

    This avoids forcing a 3D categorical visualization while still showing how
    cR and cI jointly affect the equilibrium at low, reference, critical-near,
    and high rate-limiting costs.
    """
    available_cD = sorted({float(r["cD"]) for r in rows})
    requested = [0.10, 0.20, 0.25, 0.35]
    selected = [min(available_cD, key=lambda x: abs(x - target)) for target in requested]
    selected = list(dict.fromkeys(selected))

    for cD in selected:
        subset = [r for r in rows if abs(float(r["cD"]) - cD) <= EPS]
        cR_values = sorted({float(r["cR"]) for r in subset})
        cI_values = sorted({float(r["cI"]) for r in subset})
        equilibria = sorted({str(r["equilibrium_pairs"]) for r in subset})
        eq_to_code = {eq: i for i, eq in enumerate(equilibria)}

        grid = np.full((len(cI_values), len(cR_values)), np.nan)
        cR_index = {v: i for i, v in enumerate(cR_values)}
        cI_index = {v: i for i, v in enumerate(cI_values)}

        for row in subset:
            x = cR_index[float(row["cR"])]
            y = cI_index[float(row["cI"])]
            grid[y, x] = eq_to_code[str(row["equilibrium_pairs"])]

        fig, ax = plt.subplots(figsize=(8, 6))
        image = ax.imshow(
            grid,
            origin="lower",
            aspect="auto",
            extent=[
                min(cR_values),
                max(cR_values),
                min(cI_values),
                max(cI_values),
            ],
            interpolation="nearest",
        )
        ax.set_xlabel(r"Freshness cost $c_R$")
        ax.set_ylabel(r"Auth/ACL cost $c_I$")
        ax.set_title(rf"Defender-cost phase map at $c_D={cD:.2f}$")

        ticks = list(range(len(equilibria)))
        cbar = fig.colorbar(image, ax=ax, ticks=ticks)
        cbar.ax.set_yticklabels(equilibria)
        cbar.set_label("Equilibrium pair")

        fig.tight_layout()
        filename = f"experiment_A_phase_cD_{cD:.2f}.png"
        fig.savefig(out_dir / filename, dpi=300, bbox_inches="tight")
        plt.close(fig)


def create_visualizations(
    out_dir: Path,
    rows_a: List[Dict[str, object]],
    rows_b: List[Dict[str, object]],
    rows_c: List[Dict[str, object]],
    tie_break: str,
) -> None:
    """Generate all cost-sensitivity figures."""
    figures_dir = out_dir / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)

    plot_reference_defender_values(figures_dir, tie_break)

    plot_equilibrium_counts(
        rows_a,
        figures_dir / "experiment_A_equilibrium_counts.png",
        "Experiment A: equilibrium distribution across defender costs",
    )

    plot_equilibrium_counts(
        rows_b,
        figures_dir / "experiment_B_equilibrium_counts.png",
        "Experiment B: equilibrium distribution across attacker costs",
    )

    plot_equilibrium_counts(
        rows_c,
        figures_dir / "experiment_C_equilibrium_counts.png",
        "Experiment C: equilibrium distribution in the joint cost sweep",
    )

    plot_experiment_c_phase_map(
        rows_c,
        figures_dir / "experiment_C_phase_map.png",
    )

    plot_experiment_a_phase_slices(rows_a, figures_dir)

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        default="stackelberg_cost_sensitivity",
        help="Directory for CSV outputs",
    )
    parser.add_argument(
        "--tie-break",
        choices=["strong", "weak"],
        default="strong",
        help="Follower tie-breaking convention",
    )
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print_reference_result(args.tie_break)

    rows_a = experiment_a(out_dir, args.tie_break)
    rows_b = experiment_b(out_dir, args.tie_break)
    rows_c = experiment_c(out_dir, args.tie_break)

    all_rows = rows_a + rows_b + rows_c
    summarize(all_rows, out_dir)

    create_visualizations(
        out_dir=out_dir,
        rows_a=rows_a,
        rows_b=rows_b,
        rows_c=rows_c,
        tie_break=args.tie_break,
    )

    print()
    print("Finished.")
    print(f"Output directory: {out_dir.resolve()}")
    print(f"Experiment A rows: {len(rows_a)}")
    print(f"Experiment B rows: {len(rows_b)}")
    print(f"Experiment C rows: {len(rows_c)}")
    print(f"Figures directory: {(out_dir / 'figures').resolve()}")


if __name__ == "__main__":
    main()
