import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import glob
import os
import time

# ── PAGE CONFIG ───────────────────────────────────────────
st.set_page_config(
    page_title="Guardrail Under Fire",
    page_icon="🔥",
    layout="wide"
)

# ── CONSTANTS ─────────────────────────────────────────────
TOTAL_EXPECTED   = 240   # 20 prompts x 6 models x 2 modes (raw + cleaned)
REFRESH_INTERVAL = 5

MODEL_FAMILIES = {
    "llama2:latestsmallermodel":  ("Llama", "small", "6.74B"),
    "llama3.1:8b":                ("Llama", "large", "8B"),
    "gemma3:4b_smallermodel":     ("Gemma", "small", "4.3B"),
    "gemma3:12blargermodel":      ("Gemma", "large", "12.2B"),
    "qwen:latest_smallermodel":   ("Qwen",  "small", "3.95B"),
    "qwen2.5:14b_largermodel":    ("Qwen",  "large", "14.2B"),
}

VERDICT_COLORS = {
    "Unsafe":    "#ff4b4b",
    "Safe":      "#00c853",
    "Partial":   "#ffa726",
    "Ambiguous": "#9e9e9e",
    "Blocked":   "#1F4E79",
    "Error":     "#616161",
}

ACTION_COLORS = {
    "CLEAN":    "#00c853",
    "SANITIZE": "#ffa726",
    "BLOCK":    "#ff4b4b",
}

def model_label(m):
    fam, size, params = MODEL_FAMILIES.get(m, ("Unknown", "?", "?"))
    return f"{fam} {size} ({params})"

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
        df["model_family"]     = df["model"].map(lambda m: MODEL_FAMILIES.get(m, ("Unknown","?","?"))[0])
        df["model_size_class"] = df["model"].map(lambda m: MODEL_FAMILIES.get(m, ("Unknown","?","?"))[1])
        df["model_params"]     = df["model"].map(lambda m: MODEL_FAMILIES.get(m, ("Unknown","?","?"))[2])
        df["model_label"]      = df["model_family"] + " (" + df["model_params"] + ")"
        if "run_mode"         not in df.columns: df["run_mode"]         = "raw"
        if "cleaner_action"   not in df.columns: df["cleaner_action"]   = "UNKNOWN"
        if "cleaner_score"    not in df.columns: df["cleaner_score"]    = 0
        if "cleaner_patterns" not in df.columns: df["cleaner_patterns"] = ""
        return df
    except Exception:
        return pd.DataFrame()

# ── SIDEBAR ───────────────────────────────────────────────
with st.sidebar:
    st.title("Guardrail Under Fire")
    st.caption("Live Red-Teaming Dashboard")
    st.markdown("---")
    st.markdown("**Experiment Config**")
    st.markdown("- 6 Target Models (3 families)")
    st.markdown("- 3 Judge Models (Ensemble)")
    st.markdown("- 4 Attack Categories")
    st.markdown("- 40 Adversarial Prompts")
    st.markdown("- Majority Vote Scoring")
    st.markdown("- Prompt Cleaner Defense Layer")
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
st.title("Guardrail Under Fire — Live Attack Dashboard")
st.caption("Real-time visualization of adversarial prompt testing across Small vs. Large LLMs with Prompt Cleaner Defense")

df_all = load_latest_results()

# ── PROGRESS ──────────────────────────────────────────────
completed = len(df_all) if not df_all.empty else 0
progress  = min(completed / TOTAL_EXPECTED, 1.0)

st.markdown("### Experiment Progress")
col_p1, col_p2, col_p3 = st.columns([6, 1, 1])
with col_p1:
    st.progress(progress)
with col_p2:
    st.metric("Completed", completed)
with col_p3:
    st.metric("Remaining", max(TOTAL_EXPECTED - completed, 0))

st.markdown("---")

if df_all.empty:
    st.info("Waiting for experiment to start. Run python3 test_vulnerabilities.py in your terminal.")
    st.stop()

# ── MODE FILTER ───────────────────────────────────────────
available_modes = sorted(df_all["run_mode"].unique().tolist())
has_both_modes  = "raw" in available_modes and "cleaned" in available_modes

st.markdown("### Mode Filter")
mode_options = available_modes + (["Both (side by side)"] if has_both_modes else [])
mode_filter  = st.radio("Show results for:", options=mode_options, horizontal=True, index=0)

df = df_all if mode_filter == "Both (side by side)" else df_all[df_all["run_mode"] == mode_filter].copy()

st.markdown("---")

# ── TOP METRICS ───────────────────────────────────────────
st.markdown("### Live Verdict Summary")

total       = len(df)
unsafe      = len(df[df["final_verdict"] == "Unsafe"])
safe        = len(df[df["final_verdict"] == "Safe"])
partial     = len(df[df["final_verdict"] == "Partial"])
ambig       = len(df[df["final_verdict"] == "Ambiguous"])
blocked     = len(df[df["final_verdict"] == "Blocked"])
overall_asr = round(unsafe / total * 100, 1) if total > 0 else 0

m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Overall ASR",          f"{overall_asr}%")
m2.metric("Unsafe (Failed)",      unsafe)
m3.metric("Safe (Held)",          safe)
m4.metric("Partial",              partial)
m5.metric("Ambiguous",            ambig)
m6.metric("Blocked by Cleaner",   blocked)

st.markdown("---")

# ── PROMPT CLEANER SECTION ────────────────────────────────
st.markdown("### Prompt Cleaner Defense Analysis")
st.caption("Rule-based sanitization layer — intercepts adversarial prompts before they reach any model")

df_raw_dedup = df_all[df_all["run_mode"] == "raw"].drop_duplicates(subset=["prompt_id"])

if not df_raw_dedup.empty and "cleaner_action" in df_raw_dedup.columns:
    total_p    = len(df_raw_dedup)
    clean_n    = len(df_raw_dedup[df_raw_dedup["cleaner_action"] == "CLEAN"])
    sanitize_n = len(df_raw_dedup[df_raw_dedup["cleaner_action"] == "SANITIZE"])
    block_n    = len(df_raw_dedup[df_raw_dedup["cleaner_action"] == "BLOCK"])

    cl1, cl2, cl3, cl4 = st.columns(4)
    cl1.metric("Total Prompts Analyzed", total_p)
    cl2.metric("CLEAN (passed through)", clean_n)
    cl3.metric("SANITIZE (rewritten)",   sanitize_n)
    cl4.metric("BLOCK (rejected)",       block_n)

    cc1, cc2 = st.columns(2)
    with cc1:
        action_counts = df_raw_dedup["cleaner_action"].value_counts().reset_index()
        action_counts.columns = ["Action", "Count"]
        fig_action = px.pie(
            action_counts, names="Action", values="Count",
            color="Action",
            color_discrete_map=ACTION_COLORS,
            title="Cleaner Action Distribution across 40 Prompts",
            hole=0.4,
        )
        st.plotly_chart(fig_action, use_container_width=True)

    with cc2:
        cat_action = df_raw_dedup.groupby(["category", "cleaner_action"]).size().reset_index(name="Count")
        fig_cat_act = px.bar(
            cat_action, x="category", y="Count", color="cleaner_action",
            barmode="stack",
            color_discrete_map=ACTION_COLORS,
            title="Cleaner Action Breakdown by Attack Category",
            labels={"category": "Category", "cleaner_action": "Action"},
        )
        fig_cat_act.update_layout(xaxis=dict(tickangle=15))
        st.plotly_chart(fig_cat_act, use_container_width=True)

    if "cleaner_score" in df_raw_dedup.columns:
        fig_score = px.histogram(
            df_raw_dedup, x="cleaner_score", nbins=20,
            color="cleaner_action",
            color_discrete_map=ACTION_COLORS,
            title="Threat Score Distribution per Prompt (0 = benign, 60+ = BLOCK threshold)",
            labels={"cleaner_score": "Threat Score", "cleaner_action": "Action"},
        )
        fig_score.add_vline(x=60, line_dash="dash", line_color="red",
                            annotation_text="BLOCK threshold",
                            annotation_position="top right")
        st.plotly_chart(fig_score, use_container_width=True)

st.markdown("---")

# ── RAW vs CLEANED ASR COMPARISON ────────────────────────
if has_both_modes:
    st.markdown("### Raw vs. Cleaned ASR Comparison")
    st.caption("Measured effectiveness of the Prompt Cleaner — lower cleaned ASR means the defense is working")

    raw_df     = df_all[df_all["run_mode"] == "raw"]
    cleaned_df = df_all[df_all["run_mode"] == "cleaned"]

    compare_rows = []
    for model in df_all["model"].unique():
        raw_m   = raw_df[raw_df["model"] == model]
        clean_m = cleaned_df[cleaned_df["model"] == model]
        if len(raw_m) > 0 and len(clean_m) > 0:
            raw_asr   = round(len(raw_m[raw_m["final_verdict"]     == "Unsafe"]) / len(raw_m)   * 100, 1)
            clean_asr = round(len(clean_m[clean_m["final_verdict"] == "Unsafe"]) / len(clean_m) * 100, 1)
            fam, size, params = MODEL_FAMILIES.get(model, ("?","?","?"))
            compare_rows.append({
                "Model":           f"{fam} {size} ({params})",
                "Raw ASR (%)":     raw_asr,
                "Cleaned ASR (%)": clean_asr,
                "Reduction (%)":   round(raw_asr - clean_asr, 1),
            })

    if compare_rows:
        compare_df   = pd.DataFrame(compare_rows)
        compare_melt = compare_df.melt(
            id_vars="Model",
            value_vars=["Raw ASR (%)", "Cleaned ASR (%)"],
            var_name="Mode", value_name="ASR (%)"
        )
        fig_cmp = px.bar(
            compare_melt, x="Model", y="ASR (%)", color="Mode",
            barmode="group", text="ASR (%)",
            color_discrete_map={"Raw ASR (%)": "#ff4b4b", "Cleaned ASR (%)": "#2196f3"},
            title="Raw vs. Cleaned ASR per Model",
        )
        fig_cmp.update_traces(texttemplate="%{text}%", textposition="outside")
        fig_cmp.update_layout(yaxis_range=[0, 110], xaxis=dict(tickangle=15))
        st.plotly_chart(fig_cmp, use_container_width=True)

        st.dataframe(
            compare_df[["Model", "Raw ASR (%)", "Cleaned ASR (%)", "Reduction (%)"]],
            use_container_width=True, hide_index=True
        )

        raw_unsafe  = raw_df[raw_df["final_verdict"] == "Unsafe"].shape[0]
        cln_unsafe  = cleaned_df[cleaned_df["final_verdict"] == "Unsafe"].shape[0]
        oa_raw      = round(raw_unsafe  / len(raw_df)     * 100, 1) if len(raw_df)     > 0 else 0
        oa_clean    = round(cln_unsafe  / len(cleaned_df) * 100, 1) if len(cleaned_df) > 0 else 0
        rc1, rc2, rc3 = st.columns(3)
        rc1.metric("Overall Raw ASR",     f"{oa_raw}%")
        rc2.metric("Overall Cleaned ASR", f"{oa_clean}%")
        rc3.metric("Total ASR Reduction", f"{round(oa_raw - oa_clean, 1)}%",
                   delta=f"-{round(oa_raw - oa_clean, 1)}%", delta_color="inverse")

    st.markdown("---")

# ── SMALL vs LARGE ────────────────────────────────────────
st.markdown("### Small vs. Large Guardrail Strength by Family")
st.caption("Core research finding — lower ASR = stronger guardrail")

family_size = df.groupby(["model_family", "model_size_class", "model_params"]).apply(
    lambda x: round(len(x[x["final_verdict"] == "Unsafe"]) / len(x) * 100, 1) if len(x) > 0 else 0
).reset_index()
family_size.columns = ["Family", "Size", "Params", "ASR (%)"]

fig_sv = px.bar(
    family_size, x="Family", y="ASR (%)", color="Size",
    barmode="group", text="ASR (%)",
    color_discrete_map={"small": "#ff4b4b", "large": "#2196f3"},
    title="Attack Success Rate: Small vs. Large per Model Family",
)
fig_sv.update_traces(texttemplate="%{text}%", textposition="outside")
fig_sv.update_layout(yaxis_range=[0, 110], legend_title="Model Size")
st.plotly_chart(fig_sv, use_container_width=True)

st.markdown("---")

# ── ASR HEATMAP ───────────────────────────────────────────
st.markdown("### ASR Heatmap — Attack Category x Model")
st.caption("Darker red = higher vulnerability")

pivot = df.groupby(["category", "model_label"]).apply(
    lambda x: round(len(x[x["final_verdict"] == "Unsafe"]) / len(x) * 100, 1) if len(x) > 0 else 0
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

# ── CROSS-MODEL TRANSFER MATRIX ───────────────────────────
st.markdown("### Cross-Model Transfer Matrix")
st.caption("For each source model, what percentage of its Unsafe prompts were also Unsafe on each target model")

models = df["model"].unique().tolist()
if len(models) > 1:
    prompt_model_unsafe = df[df["final_verdict"] == "Unsafe"][["prompt_id", "model"]].copy()
    transfer_data = {}
    for source in models:
        src_unsafe = set(prompt_model_unsafe[prompt_model_unsafe["model"] == source]["prompt_id"])
        row = {}
        for target in models:
            tgt_unsafe = set(prompt_model_unsafe[prompt_model_unsafe["model"] == target]["prompt_id"])
            row[target] = round(len(src_unsafe & tgt_unsafe) / len(src_unsafe) * 100, 1) if src_unsafe else 0.0
        transfer_data[source] = row

    transfer_df         = pd.DataFrame(transfer_data).T
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
        title="Cross-Model Attack Transfer Matrix",
        xaxis=dict(title="Target Model", tickangle=20),
        yaxis=dict(title="Source Model"),
        height=420,
    )
    st.plotly_chart(fig_transfer, use_container_width=True)
    st.caption("Diagonal = self-consistency. High off-diagonal values indicate attacks transfer broadly across model families.")
else:
    st.info("Transfer matrix requires results from at least 2 models.")

st.markdown("---")

# ── CUMULATIVE UNSAFE ─────────────────────────────────────
st.markdown("### Cumulative Unsafe Verdicts Over Prompts")
st.caption("Sharp rises reveal which attack category caused breakthroughs")

if "prompt_id" in df.columns:
    prompt_order    = df["prompt_id"].unique().tolist()
    cumulative_rows = []
    for model in df["model"].unique():
        model_df = df[df["model"] == model].copy()
        label    = model_df["model_label"].iloc[0]
        count    = 0
        for i, pid in enumerate(prompt_order):
            row = model_df[model_df["prompt_id"] == pid]
            if not row.empty and row.iloc[0]["final_verdict"] == "Unsafe":
                count += 1
            cumulative_rows.append({"Prompt Index": i + 1, "Cumulative Unsafe": count, "Model": label})
    cum_df  = pd.DataFrame(cumulative_rows)
    fig_cum = px.line(
        cum_df, x="Prompt Index", y="Cumulative Unsafe", color="Model",
        title="Cumulative Unsafe Verdicts per Model as Prompts Progress",
        markers=True,
    )
    st.plotly_chart(fig_cum, use_container_width=True)

st.markdown("---")

# ── VERDICT BREAKDOWN ─────────────────────────────────────
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
        lambda x: round(len(x[x["final_verdict"] == "Unsafe"]) / len(x) * 100, 1) if len(x) > 0 else 0
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

# ── JUDGE AGREEMENT ───────────────────────────────────────
st.markdown("### Judge Ensemble Agreement Analysis")
st.caption("Inter-judge agreement rate — how often each pair of judges agreed on the same verdict")

judge_cols = ["judge_1_verdict", "judge_2_verdict", "judge_3_verdict"]
if all(c in df.columns for c in judge_cols):
    total_rows = len(df)
    all_agree  = df.apply(
        lambda r: r["judge_1_verdict"] == r["judge_2_verdict"] == r["judge_3_verdict"], axis=1
    ).sum()
    pct_all = round(all_agree / total_rows * 100, 1) if total_rows > 0 else 0

    pairs = [
        ("Judge 1 vs 2", "judge_1_verdict", "judge_2_verdict"),
        ("Judge 1 vs 3", "judge_1_verdict", "judge_3_verdict"),
        ("Judge 2 vs 3", "judge_2_verdict", "judge_3_verdict"),
    ]
    agree_rows = []
    for label, c1, c2 in pairs:
        pct = round((df[c1] == df[c2]).sum() / total_rows * 100, 1) if total_rows > 0 else 0
        agree_rows.append({"Judge Pair": label, "Agreement Rate (%)": pct})
    agree_df = pd.DataFrame(agree_rows)

    ja1, ja2, ja3 = st.columns(3)
    ja1.metric("All 3 Judges Agree", f"{pct_all}%")
    ja2.metric("Unanimous Safe",   f"{round(len(df[(df['judge_1_verdict']=='Safe')   & (df['judge_2_verdict']=='Safe')   & (df['judge_3_verdict']=='Safe')]  ) / total_rows * 100, 1)}%")
    ja3.metric("Unanimous Unsafe", f"{round(len(df[(df['judge_1_verdict']=='Unsafe') & (df['judge_2_verdict']=='Unsafe') & (df['judge_3_verdict']=='Unsafe')]) / total_rows * 100, 1)}%")

    jc1, jc2 = st.columns(2)
    with jc1:
        fig_agree = px.bar(
            agree_df, x="Judge Pair", y="Agreement Rate (%)",
            color="Agreement Rate (%)",
            color_continuous_scale="Blues",
            text="Agreement Rate (%)",
            title="Pairwise Judge Agreement Rate",
        )
        fig_agree.update_traces(texttemplate="%{text}%", textposition="outside")
        fig_agree.update_layout(yaxis_range=[0, 110], showlegend=False)
        st.plotly_chart(fig_agree, use_container_width=True)

    with jc2:
        verdict_options = ["Safe", "Unsafe", "Partial"]
        agree_matrix    = pd.DataFrame(index=verdict_options, columns=verdict_options, dtype=float)
        for v1 in verdict_options:
            for v2 in verdict_options:
                agree_matrix.loc[v1, v2] = len(df[(df["judge_1_verdict"] == v1) & (df["judge_2_verdict"] == v2)])
        fig_vheat = go.Figure(data=go.Heatmap(
            z=agree_matrix.values.astype(float),
            x=verdict_options, y=verdict_options,
            colorscale="Blues",
            text=agree_matrix.values.astype(int),
            texttemplate="%{text}",
            showscale=True,
            colorbar=dict(title="Count"),
        ))
        fig_vheat.update_layout(
            title="Judge 1 vs Judge 2 Verdict Agreement Matrix",
            xaxis_title="Judge 2 Verdict",
            yaxis_title="Judge 1 Verdict",
            height=300,
        )
        st.plotly_chart(fig_vheat, use_container_width=True)

st.markdown("---")

# ── RESPONSE TIME ─────────────────────────────────────────
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

# ── MITRE / OWASP ─────────────────────────────────────────
st.markdown("### MITRE ATLAS and OWASP Mapping")
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

# ── LIVE FEED ─────────────────────────────────────────────
st.markdown("### Live Results Feed (Last 20 Rows)")
display_cols = [c for c in [
    "run_mode", "prompt_id", "category", "cleaner_action",
    "model_family", "model_size_class", "model_params",
    "final_verdict", "response_time_sec"
] if c in df.columns]
recent = df[display_cols].tail(20).iloc[::-1].copy()
st.dataframe(recent, use_container_width=True, hide_index=True)

st.markdown("---")

# ── EXPORT ────────────────────────────────────────────────
csv_export = df_all.to_csv(index=False).encode("utf-8")
st.download_button(
    label="Download Full Results CSV",
    data=csv_export,
    file_name="guardrail_results_full.csv",
    mime="text/csv"
)

# ── AUTO REFRESH ──────────────────────────────────────────
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()
