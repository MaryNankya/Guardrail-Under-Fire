import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import glob
import os
import time
import numpy as np

# ── PAGE CONFIG ───────────────────────────────────────────
st.set_page_config(
    page_title="Guardrail Under Fire",
    page_icon="🔥",
    layout="wide"
)

# ── CONSTANTS ─────────────────────────────────────────────
TOTAL_EXPECTED   = 72   # 12 prompts x 6 models (3 per category x 4 categories)
REFRESH_INTERVAL = 5

MODEL_FAMILIES = {
    "llama2:latestsmallermodel":  ("Llama",  "small",  "6.74B"),
    "llama3.1:8b":                ("Llama",  "large",  "8B"),
    "gemma3:4b_smallermodel":     ("Gemma",  "small",  "4.3B"),
    "gemma3:12blargermodel":      ("Gemma",  "large",  "12.2B"),
    "qwen:latest_smallermodel":   ("Qwen",   "small",  "3.95B"),
    "qwen2.5:14b_largermodel":    ("Qwen",   "large",  "14.2B"),
}

VERDICT_COLORS = {
    "Unsafe":    "#ff4b4b",
    "Safe":      "#00c853",
    "Partial":   "#ffa726",
    "Ambiguous": "#9e9e9e",
    "Error":     "#616161",
}

MODEL_ORDER = [
    "llama2:latestsmallermodel",
    "gemma3:4b_smallermodel",
    "qwen:latest_smallermodel",
    "llama3.1:8b",
    "gemma3:12blargermodel",
    "qwen2.5:14b_largermodel",
]

# ── LOAD LATEST CSV ───────────────────────────────────────
def load_latest_results():
    files = glob.glob("results_*.csv")
    if not files:
        return pd.DataFrame()
    latest = max(files, key=os.path.getmtime)
    try:
        df = pd.read_csv(latest)
        if df.empty:
            return pd.DataFrame()
        df["model_family"]     = df["model"].map(lambda m: MODEL_FAMILIES.get(m, ("Unknown","unknown","?"))[0])
        df["model_size_class"] = df["model"].map(lambda m: MODEL_FAMILIES.get(m, ("Unknown","unknown","?"))[1])
        df["model_params"]     = df["model"].map(lambda m: MODEL_FAMILIES.get(m, ("Unknown","unknown","?"))[2])
        df["model_label"]      = df["model_family"] + " (" + df["model_params"] + ")"
        return df
    except Exception:
        return pd.DataFrame()

# ── SIDEBAR ───────────────────────────────────────────────
with st.sidebar:
    st.title("🔥 Guardrail Under Fire")
    st.caption("Live Red-Teaming Dashboard")
    st.markdown("---")
    st.markdown("**Experiment Config**")
    st.markdown("- 6 Target Models (3 families)")
    st.markdown("- 3 Judge Models (Ensemble)")
    st.markdown("- 4 Attack Categories")
    st.markdown("- Majority Vote Scoring")
    st.markdown("---")
    auto_refresh = st.toggle("Auto-Refresh", value=True)
    refresh_rate = st.slider("Refresh every (sec)", 3, 30, REFRESH_INTERVAL)
    if st.button("Force Refresh Now"):
        st.rerun()
    st.markdown("---")
    st.markdown("**MITRE ATLAS**")
    st.markdown("AML.T0043 · AML.T0051 · AML.T0054")
    st.markdown("**OWASP LLM Top 10**")
    st.markdown("LLM01 · LLM02")

# ── MAIN ──────────────────────────────────────────────────
st.title("🔥 Guardrail Under Fire — Live Attack Dashboard")
st.caption("Real-time visualization of adversarial prompt testing across Small vs. Large LLMs")

df = load_latest_results()

# ── PROGRESS ──────────────────────────────────────────────
completed = len(df) if not df.empty else 0
progress  = min(completed / TOTAL_EXPECTED, 1.0)

st.markdown("### Experiment Progress")
col_p1, col_p2, col_p3 = st.columns([6, 1, 1])
with col_p1:
    st.progress(progress)
with col_p2:
    st.metric("Completed", completed)
with col_p3:
    st.metric("Remaining", TOTAL_EXPECTED - completed)

st.markdown("---")

if df.empty:
    st.info("Waiting for experiment to start... Run `python3 test_vulnerabilities.py` in your terminal.")
else:
    # ── TOP METRICS ───────────────────────────────────────
    st.markdown("### Live Verdict Summary")
    total       = len(df)
    unsafe      = len(df[df["final_verdict"] == "Unsafe"])
    safe        = len(df[df["final_verdict"] == "Safe"])
    partial     = len(df[df["final_verdict"] == "Partial"])
    ambig       = len(df[df["final_verdict"] == "Ambiguous"])
    overall_asr = round(unsafe / total * 100, 1) if total > 0 else 0

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Overall ASR",     f"{overall_asr}%")
    m2.metric("Unsafe (Failed)", unsafe)
    m3.metric("Safe (Held)",     safe)
    m4.metric("Partial",         partial)
    m5.metric("Ambiguous",       ambig)

    st.markdown("---")

    # ── SMALL vs LARGE ────────────────────────────────────
    st.markdown("### Small vs. Large Guardrail Strength by Family")
    st.caption("Core research finding — lower ASR = stronger guardrail")

    family_size = df.groupby(["model_family", "model_size_class", "model_params"]).apply(
        lambda x: round(len(x[x["final_verdict"] == "Unsafe"]) / len(x) * 100, 1)
        if len(x) > 0 else 0
    ).reset_index()
    family_size.columns = ["Family", "Size", "Params", "ASR (%)"]

    fig_compare = px.bar(
        family_size, x="Family", y="ASR (%)", color="Size",
        barmode="group", text="ASR (%)",
        color_discrete_map={"small": "#ff4b4b", "large": "#2196f3"},
        title="Attack Success Rate: Small vs. Large per Model Family",
    )
    fig_compare.update_traces(texttemplate="%{text}%", textposition="outside")
    fig_compare.update_layout(yaxis_range=[0, 110], legend_title="Model Size")
    st.plotly_chart(fig_compare, use_container_width=True)

    st.markdown("---")

    # ── ASR HEATMAP ───────────────────────────────────────
    st.markdown("### ASR Heatmap — Attack Category × Model")
    st.caption("Darker red = higher vulnerability")

    pivot = df.groupby(["category", "model_label"]).apply(
        lambda x: round(len(x[x["final_verdict"] == "Unsafe"]) / len(x) * 100, 1)
        if len(x) > 0 else 0
    ).reset_index()
    pivot.columns = ["Category", "Model", "ASR (%)"]

    if not pivot.empty:
        heatmap_data = pivot.pivot(index="Category", columns="Model", values="ASR (%)").fillna(0)
        fig_heat = go.Figure(data=go.Heatmap(
            z=heatmap_data.values,
            x=heatmap_data.columns.tolist(),
            y=heatmap_data.index.tolist(),
            colorscale="Reds",
            text=[[f"{v:.1f}%" for v in row] for row in heatmap_data.values],
            texttemplate="%{text}",
            showscale=True,
        ))
        fig_heat.update_layout(title="ASR Heatmap", xaxis=dict(tickangle=20))
        st.plotly_chart(fig_heat, use_container_width=True)

    st.markdown("---")

    # ── CROSS-MODEL TRANSFER MATRIX ───────────────────────
    st.markdown("### Cross-Model Transfer Matrix")
    st.caption("For each source model (row), what % of its Unsafe prompts were also Unsafe on each target model (column) — inspired by Dziemian et al. 2026")

    models = df["model"].unique().tolist()
    if len(models) > 1:
        # For each prompt, collect which models marked it Unsafe
        prompt_model_unsafe = df[df["final_verdict"] == "Unsafe"][["prompt_id", "model"]].copy()

        transfer_data = {}
        for source in models:
            source_unsafe_prompts = set(
                prompt_model_unsafe[prompt_model_unsafe["model"] == source]["prompt_id"]
            )
            row = {}
            for target in models:
                if len(source_unsafe_prompts) == 0:
                    row[target] = 0.0
                else:
                    target_unsafe_prompts = set(
                        prompt_model_unsafe[prompt_model_unsafe["model"] == target]["prompt_id"]
                    )
                    overlap = source_unsafe_prompts & target_unsafe_prompts
                    row[target] = round(len(overlap) / len(source_unsafe_prompts) * 100, 1)
            transfer_data[source] = row

        transfer_df = pd.DataFrame(transfer_data).T

        # Build nice labels
        def model_label(m):
            fam = MODEL_FAMILIES.get(m, ("?","?","?"))
            return f"{fam[0]} {fam[1]} ({fam[2]})"

        transfer_df.index   = [model_label(m) for m in transfer_df.index]
        transfer_df.columns = [model_label(m) for m in transfer_df.columns]

        fig_transfer = go.Figure(data=go.Heatmap(
            z=transfer_df.values,
            x=transfer_df.columns.tolist(),
            y=transfer_df.index.tolist(),
            colorscale="RdYlGn_r",
            text=[[f"{v:.0f}%" for v in row] for row in transfer_df.values],
            texttemplate="%{text}",
            showscale=True,
            colorbar=dict(title="Transfer %"),
            zmin=0, zmax=100,
        ))
        fig_transfer.update_layout(
            title="Cross-Model Attack Transfer Matrix (% of source Unsafe prompts also Unsafe on target)",
            xaxis=dict(title="Target Model", tickangle=20),
            yaxis=dict(title="Source Model"),
            height=420,
        )
        st.plotly_chart(fig_transfer, use_container_width=True)
        st.caption("Diagonal = self-consistency. High off-diagonal values = attacks transfer broadly across models.")
    else:
        st.info("Transfer matrix requires results from at least 2 models.")

    st.markdown("---")

    # ── CUMULATIVE UNSAFE OVER PROMPTS ────────────────────
    st.markdown("### Cumulative Unsafe Verdicts Over Prompts")
    st.caption("Shows when vulnerability was discovered — sharp rises indicate effective attack categories")

    if "prompt_id" in df.columns:
        prompt_order = df["prompt_id"].unique().tolist()
        cumulative_rows = []
        for model in df["model"].unique():
            model_df  = df[df["model"] == model].copy()
            label     = model_label(model) if "model_label" not in model_df.columns else model_df["model_label"].iloc[0]
            count     = 0
            for i, pid in enumerate(prompt_order):
                row = model_df[model_df["prompt_id"] == pid]
                if not row.empty and row.iloc[0]["final_verdict"] == "Unsafe":
                    count += 1
                cumulative_rows.append({"Prompt Index": i + 1, "Cumulative Unsafe": count, "Model": label})

        cum_df = pd.DataFrame(cumulative_rows)
        fig_cum = px.line(
            cum_df, x="Prompt Index", y="Cumulative Unsafe", color="Model",
            title="Cumulative Unsafe Verdicts per Model as Prompts Progress",
            markers=True,
        )
        fig_cum.update_layout(yaxis_title="Cumulative Unsafe Count", xaxis_title="Prompt Number")
        st.plotly_chart(fig_cum, use_container_width=True)

    st.markdown("---")

    # ── VERDICT DISTRIBUTION ──────────────────────────────
    st.markdown("### Verdict Breakdown")
    col_v1, col_v2 = st.columns(2)

    with col_v1:
        verdict_counts = df.groupby(["model_label", "final_verdict"]).size().reset_index(name="Count")
        fig_verdict = px.bar(
            verdict_counts, x="model_label", y="Count", color="final_verdict",
            barmode="stack",
            color_discrete_map=VERDICT_COLORS,
            title="Verdict Breakdown per Model",
            labels={"model_label": "Model", "final_verdict": "Verdict"}
        )
        fig_verdict.update_layout(xaxis=dict(tickangle=25))
        st.plotly_chart(fig_verdict, use_container_width=True)

    with col_v2:
        cat_asr = df.groupby("category").apply(
            lambda x: round(len(x[x["final_verdict"] == "Unsafe"]) / len(x) * 100, 1)
            if len(x) > 0 else 0
        ).reset_index()
        cat_asr.columns = ["Category", "ASR (%)"]
        fig_cat = px.bar(
            cat_asr, x="ASR (%)", y="Category",
            orientation="h",
            color="ASR (%)",
            color_continuous_scale="Reds",
            title="ASR by Attack Category",
            text="ASR (%)"
        )
        fig_cat.update_traces(texttemplate="%{text}%", textposition="outside")
        fig_cat.update_layout(xaxis_range=[0, 110])
        st.plotly_chart(fig_cat, use_container_width=True)

    st.markdown("---")

    # ── JUDGE AGREEMENT ANALYSIS ──────────────────────────
    st.markdown("### Judge Ensemble Agreement Analysis")
    st.caption("Inter-judge agreement rate — how often each pair of judges agreed on the same verdict")

    judge_cols = ["judge_1_verdict", "judge_2_verdict", "judge_3_verdict"]
    judge_names = ["judge_1_model", "judge_2_model", "judge_3_model"]

    if all(c in df.columns for c in judge_cols):
        # Overall agreement — all 3 judges same verdict
        all_agree = df.apply(
            lambda r: r["judge_1_verdict"] == r["judge_2_verdict"] == r["judge_3_verdict"],
            axis=1
        ).sum()
        pct_all_agree = round(all_agree / total * 100, 1)

        # Pairwise agreement
        pairs = [
            ("Judge 1 vs 2", "judge_1_verdict", "judge_2_verdict"),
            ("Judge 1 vs 3", "judge_1_verdict", "judge_3_verdict"),
            ("Judge 2 vs 3", "judge_2_verdict", "judge_3_verdict"),
        ]

        agree_rows = []
        for label, c1, c2 in pairs:
            agree = (df[c1] == df[c2]).sum()
            pct   = round(agree / total * 100, 1)
            agree_rows.append({"Judge Pair": label, "Agreement Rate (%)": pct, "Agreed Rows": agree})

        agree_df = pd.DataFrame(agree_rows)

        ja1, ja2, ja3 = st.columns(3)
        ja1.metric("All 3 Judges Agree",     f"{pct_all_agree}%")
        ja2.metric("Unanimous Safe",          f"{round(len(df[(df['judge_1_verdict']=='Safe') & (df['judge_2_verdict']=='Safe') & (df['judge_3_verdict']=='Safe')])/total*100,1)}%")
        ja3.metric("Unanimous Unsafe",        f"{round(len(df[(df['judge_1_verdict']=='Unsafe') & (df['judge_2_verdict']=='Unsafe') & (df['judge_3_verdict']=='Unsafe')])/total*100,1)}%")

        # Pairwise bar chart
        fig_agree = px.bar(
            agree_df, x="Judge Pair", y="Agreement Rate (%)",
            color="Agreement Rate (%)",
            color_continuous_scale="Blues",
            text="Agreement Rate (%)",
            title="Pairwise Judge Agreement Rate",
        )
        fig_agree.update_traces(texttemplate="%{text}%", textposition="outside")
        fig_agree.update_layout(yaxis_range=[0, 110], showlegend=False)

        # Per-verdict agreement heatmap
        verdict_options = ["Safe", "Unsafe", "Partial"]
        agree_matrix = pd.DataFrame(index=verdict_options, columns=verdict_options, dtype=float)
        for v1 in verdict_options:
            for v2 in verdict_options:
                subset = df[(df["judge_1_verdict"] == v1) & (df["judge_2_verdict"] == v2)]
                agree_matrix.loc[v1, v2] = len(subset)

        fig_vheat = go.Figure(data=go.Heatmap(
            z=agree_matrix.values.astype(float),
            x=verdict_options,
            y=verdict_options,
            colorscale="Blues",
            text=agree_matrix.values.astype(int),
            texttemplate="%{text}",
            showscale=True,
            colorbar=dict(title="Count"),
        ))
        fig_vheat.update_layout(
            title="Judge 1 vs Judge 2 — Verdict Agreement Matrix",
            xaxis_title="Judge 2 Verdict",
            yaxis_title="Judge 1 Verdict",
            height=300,
        )

        jc1, jc2 = st.columns(2)
        with jc1:
            st.plotly_chart(fig_agree, use_container_width=True)
        with jc2:
            st.plotly_chart(fig_vheat, use_container_width=True)

    st.markdown("---")

    # ── RESPONSE TIME ANALYSIS ────────────────────────────
    st.markdown("### Response Time by Model")
    st.caption("Longer times on Token Flooding prompts indicate the model attempted compliance before hitting limits")

    if "response_time_sec" in df.columns:
        time_df = df[df["response_time_sec"] > 0].copy()
        if not time_df.empty:
            fig_time = px.box(
                time_df, x="model_label", y="response_time_sec",
                color="model_size_class",
                color_discrete_map={"small": "#ff4b4b", "large": "#2196f3"},
                title="Response Time Distribution per Model",
                labels={"model_label": "Model", "response_time_sec": "Response Time (s)"},
                points="all",
            )
            fig_time.update_layout(xaxis=dict(tickangle=20), legend_title="Model Size")
            st.plotly_chart(fig_time, use_container_width=True)

    st.markdown("---")

    # ── MITRE / OWASP ─────────────────────────────────────
    st.markdown("### MITRE ATLAS & OWASP Mapping")
    unsafe_df = df[df["final_verdict"] == "Unsafe"]
    if not unsafe_df.empty:
        mc1, mc2 = st.columns(2)
        with mc1:
            st.markdown("**MITRE ATLAS Hits**")
            mitre = unsafe_df.groupby(["mitre", "category"]).size().reset_index(name="Unsafe Count")
            st.dataframe(mitre, use_container_width=True, hide_index=True)
        with mc2:
            st.markdown("**OWASP LLM Top 10 Hits**")
            owasp = unsafe_df.groupby("owasp").size().reset_index(name="Unsafe Count")
            st.dataframe(owasp, use_container_width=True, hide_index=True)
    else:
        st.info("No Unsafe verdicts recorded yet.")

    st.markdown("---")

    # ── LIVE FEED ─────────────────────────────────────────
    st.markdown("### Live Results Feed (Last 20)")
    display_cols = ["prompt_id", "category", "model_family",
                    "model_size_class", "model_params",
                    "final_verdict", "response_time_sec"]
    recent = df[display_cols].tail(20).iloc[::-1].copy()
    st.dataframe(recent, use_container_width=True, hide_index=True)

    st.markdown("---")

    # ── EXPORT ────────────────────────────────────────────
    csv_export = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Download Full Results CSV",
        data=csv_export,
        file_name="guardrail_results.csv",
        mime="text/csv"
    )

# ── AUTO REFRESH ──────────────────────────────────────────
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()
