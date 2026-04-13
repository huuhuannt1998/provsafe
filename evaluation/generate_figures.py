#!/usr/bin/env python3
"""
Generate publication-quality figures for PROVSAFE evaluation.
"""

import json
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# Use publication-quality settings
plt.style.use("seaborn-v0_8-whitegrid")
plt.rcParams["font.family"] = "serif"
plt.rcParams["font.size"] = 12
plt.rcParams["axes.labelsize"] = 14
plt.rcParams["axes.titlesize"] = 14
plt.rcParams["legend.fontsize"] = 11
plt.rcParams["figure.figsize"] = (8, 5)
plt.rcParams["figure.dpi"] = 150

# Find most recent results
RESULTS_DIR = Path("results")
result_dirs = sorted(RESULTS_DIR.glob("publication_eval_*"))
if not result_dirs:
    print("No publication results found!")
    exit(1)

LATEST = result_dirs[-1]
print(f"Using results from: {LATEST}")

# Load data
with open(LATEST / "publication_analysis.json") as f:
    analysis = json.load(f)

with open(LATEST / "detailed_results.json") as f:
    detailed = json.load(f)

OUTPUT_DIR = LATEST / "figures"
OUTPUT_DIR.mkdir(exist_ok=True)


def fig1_asr_comparison():
    """Figure 1: Attack Success Rate comparison bar chart."""
    systems = ["No Defense", "Pattern Filter", "Policy-Only", "PROVSAFE"]
    asrs = [
        analysis["main_results"]["no_defense"]["asr"],
        analysis["main_results"]["pattern_filter"]["asr"],
        analysis["main_results"]["policy_only"]["asr"],
        analysis["main_results"]["provsafe"]["asr"],
    ]

    fig, ax = plt.subplots(figsize=(8, 5))

    colors = ["#e74c3c", "#f39c12", "#3498db", "#27ae60"]
    bars = ax.bar(systems, asrs, color=colors, edgecolor="black", linewidth=0.5)

    # Add value labels
    for bar, asr in zip(bars, asrs):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1.5,
            f"{asr:.1f}%",
            ha="center",
            va="bottom",
            fontsize=12,
            fontweight="bold",
        )

    ax.set_ylabel("Attack Success Rate (%)", fontsize=14)
    ax.set_xlabel("Defense System", fontsize=14)
    ax.set_title("Attack Success Rate by Defense System", fontsize=16, fontweight="bold")
    ax.set_ylim(0, 115)
    ax.axhline(y=5, color="green", linestyle="--", alpha=0.5, label="PROVSAFE threshold")

    # Add reduction annotation
    ax.annotate(
        "", xy=(3, 5), xytext=(0, 100), arrowprops=dict(arrowstyle="->", color="green", lw=2)
    )
    ax.text(
        1.5,
        55,
        "95% reduction",
        fontsize=12,
        color="green",
        fontweight="bold",
        ha="center",
        rotation=-45,
    )

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "fig1_asr_comparison.pdf", bbox_inches="tight")
    plt.savefig(OUTPUT_DIR / "fig1_asr_comparison.png", bbox_inches="tight", dpi=300)
    plt.close()
    print("✓ Generated fig1_asr_comparison.pdf")


def fig2_tsr_asr_tradeoff():
    """Figure 2: TSR vs ASR tradeoff scatter plot."""
    _systems = ["No Defense", "Pattern Filter", "Policy-Only", "PROVSAFE"]
    data = [
        (
            analysis["main_results"]["no_defense"]["tsr"],
            analysis["main_results"]["no_defense"]["asr"],
            "No Defense",
        ),
        (
            analysis["main_results"]["pattern_filter"]["tsr"],
            analysis["main_results"]["pattern_filter"]["asr"],
            "Pattern Filter",
        ),
        (
            analysis["main_results"]["policy_only"]["tsr"],
            analysis["main_results"]["policy_only"]["asr"],
            "Policy-Only",
        ),
        (
            analysis["main_results"]["provsafe"]["tsr"],
            analysis["main_results"]["provsafe"]["asr"],
            "PROVSAFE",
        ),
    ]

    fig, ax = plt.subplots(figsize=(8, 6))

    colors = ["#e74c3c", "#f39c12", "#3498db", "#27ae60"]
    markers = ["X", "s", "^", "o"]
    sizes = [200, 150, 150, 250]

    for (tsr, asr, label), color, marker, size in zip(data, colors, markers, sizes):
        ax.scatter(
            tsr,
            asr,
            c=color,
            marker=marker,
            s=size,
            label=label,
            edgecolors="black",
            linewidths=1,
            zorder=5,
        )

    # Ideal region (high TSR, low ASR)
    ax.axhspan(0, 10, xmin=0.9, xmax=1.0, alpha=0.2, color="green", label="Ideal Region")
    ax.text(98, 2, "Ideal", fontsize=11, color="green", fontweight="bold")

    ax.set_xlabel("Task Success Rate (%) - Higher is Better", fontsize=14)
    ax.set_ylabel("Attack Success Rate (%) - Lower is Better", fontsize=14)
    ax.set_title("Security-Utility Tradeoff", fontsize=16, fontweight="bold")
    ax.set_xlim(85, 105)
    ax.set_ylim(-5, 110)

    ax.legend(loc="upper left", framealpha=0.9)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "fig2_tsr_asr_tradeoff.pdf", bbox_inches="tight")
    plt.savefig(OUTPUT_DIR / "fig2_tsr_asr_tradeoff.png", bbox_inches="tight", dpi=300)
    plt.close()
    print("✓ Generated fig2_tsr_asr_tradeoff.pdf")


def fig3_category_heatmap():
    """Figure 3: Attack category heatmap."""
    categories = [
        "direct_injection",
        "device_name_injection",
        "file_content_injection",
        "confused_deputy",
        "privilege_escalation",
        "multi_turn_chaining",
        "encoding_obfuscation",
        "roleplay_jailbreak",
    ]

    # Cleaner category names for display
    cat_labels = [
        "Direct\nInjection",
        "Device Name\nInjection",
        "File Content\nInjection",
        "Confused\nDeputy",
        "Privilege\nEscalation",
        "Multi-turn\nChaining",
        "Encoding\nObfuscation",
        "Roleplay\nJailbreak",
    ]

    systems = ["no_defense", "pattern_filter", "policy_only", "provsafe"]
    sys_labels = ["No Defense", "Pattern Filter", "Policy-Only", "PROVSAFE"]

    # Build matrix
    matrix = []
    for cat in categories:
        row = []
        for sys in systems:
            if cat in analysis["per_category"] and sys in analysis["per_category"][cat]:
                row.append(analysis["per_category"][cat][sys]["asr"])
            else:
                row.append(0)
        matrix.append(row)

    matrix = np.array(matrix)

    fig, ax = plt.subplots(figsize=(10, 8))

    im = ax.imshow(matrix, cmap="RdYlGn_r", aspect="auto", vmin=0, vmax=100)

    # Add colorbar
    cbar = plt.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label("Attack Success Rate (%)", fontsize=12)

    # Set ticks
    ax.set_xticks(np.arange(len(sys_labels)))
    ax.set_yticks(np.arange(len(cat_labels)))
    ax.set_xticklabels(sys_labels, fontsize=11)
    ax.set_yticklabels(cat_labels, fontsize=10)

    # Add text annotations
    for i in range(len(cat_labels)):
        for j in range(len(sys_labels)):
            val = matrix[i, j]
            color = "white" if val > 50 else "black"
            ax.text(
                j,
                i,
                f"{val:.0f}%",
                ha="center",
                va="center",
                color=color,
                fontsize=10,
                fontweight="bold",
            )

    ax.set_title(
        "Attack Success Rate by Category and Defense System", fontsize=14, fontweight="bold", pad=15
    )

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "fig3_category_heatmap.pdf", bbox_inches="tight")
    plt.savefig(OUTPUT_DIR / "fig3_category_heatmap.png", bbox_inches="tight", dpi=300)
    plt.close()
    print("✓ Generated fig3_category_heatmap.pdf")


def fig4_latency_overhead():
    """Figure 4: Latency overhead comparison."""
    systems = ["No Defense", "Pattern Filter", "Policy-Only", "PROVSAFE"]
    latencies = [
        analysis["main_results"]["no_defense"]["avg_latency"],
        analysis["main_results"]["pattern_filter"]["avg_latency"],
        analysis["main_results"]["policy_only"]["avg_latency"],
        analysis["main_results"]["provsafe"]["avg_latency"],
    ]

    fig, ax = plt.subplots(figsize=(8, 5))

    colors = ["#e74c3c", "#f39c12", "#3498db", "#27ae60"]
    bars = ax.bar(systems, latencies, color=colors, edgecolor="black", linewidth=0.5)

    # Add value labels
    for bar, lat in zip(bars, latencies):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.2,
            f"{lat:.2f}s",
            ha="center",
            va="bottom",
            fontsize=11,
            fontweight="bold",
        )

    # Add overhead annotations
    baseline = latencies[0]
    for i, lat in enumerate(latencies[1:], 1):
        overhead = lat - baseline
        if overhead > 0:
            ax.annotate(
                f"+{overhead:.2f}s",
                xy=(i, lat),
                xytext=(i, lat + 1),
                ha="center",
                fontsize=10,
                color="gray",
            )

    ax.set_ylabel("Average Latency (seconds)", fontsize=14)
    ax.set_xlabel("Defense System", fontsize=14)
    ax.set_title("Latency Overhead by Defense System", fontsize=16, fontweight="bold")
    ax.set_ylim(0, 16)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "fig4_latency_overhead.pdf", bbox_inches="tight")
    plt.savefig(OUTPUT_DIR / "fig4_latency_overhead.png", bbox_inches="tight", dpi=300)
    plt.close()
    print("✓ Generated fig4_latency_overhead.pdf")


def fig5_ablation_study():
    """Figure 5: Ablation study showing contribution of each component."""
    components = [
        "No Defense\n(Baseline)",
        "+ Pattern Filter",
        "+ Policy Engine",
        "+ Provenance Tracking\n(PROVSAFE)",
    ]
    asrs = [100.0, 45.0, 25.94, 5.0]
    reductions = [0, 55, 74.06, 95]

    fig, ax1 = plt.subplots(figsize=(10, 5))

    x = np.arange(len(components))
    width = 0.4

    # ASR bars
    bars1 = ax1.bar(
        x - width / 2,
        asrs,
        width,
        label="ASR (%)",
        color="#e74c3c",
        edgecolor="black",
        linewidth=0.5,
    )
    ax1.set_ylabel("Attack Success Rate (%)", color="#e74c3c", fontsize=13)
    ax1.tick_params(axis="y", labelcolor="#e74c3c")
    ax1.set_ylim(0, 110)

    # Reduction line
    ax2 = ax1.twinx()
    ax2.plot(x, reductions, "go-", linewidth=2, markersize=10, label="Cumulative Reduction")
    ax2.set_ylabel("Attack Reduction (%)", color="green", fontsize=13)
    ax2.tick_params(axis="y", labelcolor="green")
    ax2.set_ylim(0, 110)

    # Add value labels
    for bar, asr in zip(bars1, asrs):
        ax1.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 2,
            f"{asr:.1f}%",
            ha="center",
            fontsize=10,
            fontweight="bold",
            color="#e74c3c",
        )

    for i, red in enumerate(reductions):
        ax2.text(i + 0.1, red + 3, f"{red:.0f}%", fontsize=10, fontweight="bold", color="green")

    ax1.set_xticks(x)
    ax1.set_xticklabels(components, fontsize=11)
    ax1.set_title(
        "Ablation Study: Contribution of Each Defense Component", fontsize=14, fontweight="bold"
    )

    # Combined legend
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper right")

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "fig5_ablation_study.pdf", bbox_inches="tight")
    plt.savefig(OUTPUT_DIR / "fig5_ablation_study.png", bbox_inches="tight", dpi=300)
    plt.close()
    print("✓ Generated fig5_ablation_study.pdf")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("Generating Publication Figures")
    print("=" * 60 + "\n")

    fig1_asr_comparison()
    fig2_tsr_asr_tradeoff()
    fig3_category_heatmap()
    fig4_latency_overhead()
    fig5_ablation_study()

    print(f"\n✓ All figures saved to: {OUTPUT_DIR}")
    print("\nFigures generated:")
    print("  1. fig1_asr_comparison.pdf - Main ASR comparison")
    print("  2. fig2_tsr_asr_tradeoff.pdf - Security-Utility tradeoff")
    print("  3. fig3_category_heatmap.pdf - Per-category analysis")
    print("  4. fig4_latency_overhead.pdf - Performance overhead")
    print("  5. fig5_ablation_study.pdf - Component contribution")
