"""
regression_plots.py
Generates Fig 1, Fig 3, and Fig 5 for the Guardrail Under Fire paper.
Outputs both PNG (200 dpi) and PDF for LaTeX inclusion.

Usage:
    python3 regression_plots.py

Outputs:
    01_asr_vs_params_scatter.png / .pdf
    03_small_vs_large_family.png / .pdf
    05_simple_regression_table.png / .pdf
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from scipy import stats

plt.rcParams.update({
    "font.family":       "DejaVu Sans",
    "font.size":         12,
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "figure.dpi":        150,
})

def save(fig, name):
    fig.savefig(f"{name}.png", dpi=200, bbox_inches="tight")
    fig.savefig(f"{name}.pdf",           bbox_inches="tight")
    print(f"Saved: {name}.png  |  {name}.pdf")
    plt.close(fig)


# ── DATA ──────────────────────────────────────────────────────
labels  = ["Llama small\n(6.74B)", "Llama large\n(8B)",
           "Gemma small\n(4.3B)",  "Gemma large\n(12.2B)",
           "Qwen small\n(3.95B)",  "Qwen large\n(14.2B)"]
params  = np.array([6.74, 8.0, 4.3, 12.2, 3.95, 14.2])
asr     = np.array([5.0, 15.0, 35.0, 15.0, 35.0, 10.0])
families= ["Llama","Llama","Gemma","Gemma","Qwen","Qwen"]
sizes   = ["Small","Large","Small","Large","Small","Large"]

COLORS  = {"Llama": "#2196f3", "Gemma": "#ff4b4b", "Qwen": "#ff8c00"}
MARKERS = {"Small": "o", "Large": "s"}

slope, intercept, r, p, se = stats.linregress(params, asr)


# ═════════════════════════════════════════════════════════════
# FIG 1 — Scatter + regression line
# ═════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(9, 6.5))

x_line = np.linspace(3.0, 15.5, 300)
y_line = slope * x_line + intercept
n, x_m = len(params), params.mean()
se_b   = se * np.sqrt(1/n + (x_line - x_m)**2 /
                      ((params - x_m)**2).sum())

ax.fill_between(x_line, y_line - 1.96*se_b, y_line + 1.96*se_b,
                alpha=0.12, color="#555555", label="95% CI")
ax.plot(x_line, y_line, color="#444444", linewidth=1.8,
        linestyle="--", label="Regression line", zorder=3)

for i in range(n):
    ax.scatter(params[i], asr[i],
               color=COLORS[families[i]],
               marker=MARKERS[sizes[i]],
               s=180, zorder=5,
               edgecolors="white", linewidths=1.4)

# Per-point offsets tuned to prevent overlap
offsets = [
    ( 9,  6),   # Llama small  (6.74, 5)
    ( 9, -15),  # Llama large  (8.0, 15)
    (-96,  6),  # Gemma small  (4.3, 35) — push left
    ( 9,  6),   # Gemma large  (12.2, 15)
    ( 9, -15),  # Qwen small   (3.95, 35) — push below Gemma small
    ( 9,  6),   # Qwen large   (14.2, 10)
]
for i, (ox, oy) in enumerate(offsets):
    ax.annotate(
        labels[i],
        xy=(params[i], asr[i]),
        xytext=(ox, oy),
        textcoords="offset points",
        fontsize=9,
        color=COLORS[families[i]],
        arrowprops=dict(arrowstyle="-",
                        color=COLORS[families[i]],
                        lw=0.8) if abs(ox) > 20 else None,
    )

stats_txt = (f"$\\hat{{\\beta}}$ = {slope:.2f} pp/B\n"
             f"$R^2$  = {r**2:.2f}\n"
             f"$p$      = {p:.3f}  (n.s.)")
ax.text(0.03, 0.97, stats_txt, transform=ax.transAxes,
        fontsize=10, va="top",
        bbox=dict(boxstyle="round,pad=0.45", facecolor="#f5f5f5",
                  edgecolor="#bbbbbb", alpha=0.95))

legend_handles = (
    [mpatches.Patch(color=COLORS[f], label=f)
     for f in ["Llama", "Gemma", "Qwen"]] +
    [plt.Line2D([0],[0], marker="o", color="gray",
                linestyle="None", markersize=8, label="Small variant"),
     plt.Line2D([0],[0], marker="s", color="gray",
                linestyle="None", markersize=8, label="Large variant"),
     plt.Line2D([0],[0], color="#444444", linewidth=1.8,
                linestyle="--", label="Regression line")]
)
ax.legend(handles=legend_handles, fontsize=9, loc="upper right",
          framealpha=0.95, edgecolor="#cccccc")

ax.set_xlabel("Parameter Count (Billions)", fontsize=12)
ax.set_ylabel("Attack Success Rate — Raw Mode (%)", fontsize=12)
ax.set_title("ASR vs. Parameter Count\n"
             "Simple Linear Regression across Six Open-Source LLMs",
             fontsize=13, fontweight="bold", pad=12)
ax.set_xlim(2.0, 17.0)
ax.set_ylim(-5, 50)
ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v,_: f"{int(v)}%"))
ax.grid(axis="y", linestyle="--", alpha=0.4, zorder=0)
ax.set_axisbelow(True)
plt.tight_layout()
save(fig, "01_asr_vs_params_scatter")


# ═════════════════════════════════════════════════════════════
# FIG 3 — Small vs Large grouped bar chart
# ═════════════════════════════════════════════════════════════
fam_names  = ["Gemma", "Llama", "Qwen"]
small_vals = [35, 5, 35]
large_vals = [15, 15, 10]
pp_change  = [-20, +10, -25]

x     = np.arange(len(fam_names))
width = 0.35

fig, ax = plt.subplots(figsize=(8.5, 6.5))

bars_s = ax.bar(x - width/2, small_vals, width,
                label="Small variant", color="#ff5b5b", zorder=3)
bars_l = ax.bar(x + width/2, large_vals, width,
                label="Large variant", color="#3ba7ff", zorder=3)

for bar, val in zip(bars_s, small_vals):
    ax.annotate(f"{val}%",
                xy=(bar.get_x() + bar.get_width()/2, val),
                xytext=(0, 10), textcoords="offset points",
                ha="center", va="bottom",
                fontsize=13, fontweight="bold", zorder=6)

for bar, val in zip(bars_l, large_vals):
    ax.annotate(f"{val}%",
                xy=(bar.get_x() + bar.get_width()/2, val),
                xytext=(0, 10), textcoords="offset points",
                ha="center", va="bottom",
                fontsize=13, fontweight="bold", zorder=6)

for i, (sv, lv, pp) in enumerate(zip(small_vals, large_vals, pp_change)):
    xs_ = x[i] - width/2
    xl_ = x[i] + width/2
    color = "darkgreen" if pp < 0 else "darkred"
    ax.annotate(
        "",
        xy=(xl_, lv), xytext=(xs_, sv),
        arrowprops=dict(arrowstyle="-|>", color=color,
                        lw=2.0, shrinkA=26, shrinkB=26),
        zorder=4,
    )
    ax.text((xs_ + xl_)/2, max(sv, lv) + 16,
            f"{pp:+d}pp",
            ha="center", va="bottom",
            fontsize=11, fontweight="bold",
            color=color, zorder=5)

ax.set_ylim(0, 60)
ax.set_ylabel("Raw ASR (%)", fontsize=12)
ax.set_title("Small vs. Large Guardrail Strength within Each Family\n"
             "Arrow shows direction of change from small to large",
             fontsize=13, fontweight="bold", pad=14)
ax.set_xticks(x)
ax.set_xticklabels(fam_names, fontsize=12)
ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v,_: f"{int(v)}%"))
ax.grid(axis="y", linestyle="--", alpha=0.4, zorder=0)
ax.set_axisbelow(True)
ax.legend(loc="upper right", fontsize=10, framealpha=0.9)
plt.tight_layout()
save(fig, "03_small_vs_large_family")


# ═════════════════════════════════════════════════════════════
# FIG 5 — Simple regression summary table
# ═════════════════════════════════════════════════════════════
headers = ["Metric", "Value", "Interpretation"]
rows = [
    ["Slope ($\\hat{\\beta}$)", "$-2.05$ pp/B",
     "ASR decreases ~2 pp per billion parameters"],
    ["Intercept",               "$36.04$\\%",
     "Predicted ASR at zero parameters (baseline)"],
    ["$R^2$",                   "$0.447$",
     "Parameter count explains 44.7\\% of ASR variance"],
    ["$p$-value",               "$0.146$",
     "Not significant at $\\alpha = 0.05$"],
    ["Std. Error",              "$1.139$",
     "Uncertainty around the slope estimate"],
    ["Conclusion",              "n.s.",
     "No statistically significant size-safety relationship"],
]

fig, ax = plt.subplots(figsize=(10.5, 3.8))
ax.axis("off")

tbl = ax.table(
    cellText=rows,
    colLabels=headers,
    cellLoc="left",
    loc="center",
    colWidths=[0.20, 0.18, 0.58],
)
tbl.auto_set_font_size(False)
tbl.set_fontsize(11)
tbl.scale(1, 2.0)

for (row, col), cell in tbl.get_celld().items():
    cell.set_edgecolor("#cccccc")
    cell.PAD = 0.07
    if row == 0:
        cell.set_facecolor("#1F4E79")
        cell.set_text_props(color="white", fontweight="bold")
    elif row % 2 == 0:
        cell.set_facecolor("#EBF3FB")
    else:
        cell.set_facecolor("white")
    if row == len(rows) and col in [1, 2]:
        cell.set_text_props(color="#777777", style="italic")

ax.set_title(
    "Simple Linear Regression Summary — "
    "ASR $\\sim$ Parameter Count   ($n = 6$)",
    fontsize=12, fontweight="bold", pad=18, loc="left"
)
plt.tight_layout()
save(fig, "05_simple_regression_table")
