# 🛡️ Guardrail Under Fire

**An Automated Red-Teaming Dashboard for Evaluating Guardrail Strength in Small vs. Large Open-Source LLMs**

Guardrail Under Fire is a platform that measures how well open-source LLMs resist adversarial prompt attacks. It tests six models from three families against 20 curated attack prompts, scores every response using an independent judge ensemble, and maps all confirmed failures to [MITRE ATLAS](https://atlas.mitre.org) and [OWASP LLM Top 10](https://genai.owasp.org). The platform includes a **Prompt Cleaner** defense layer that intercepts adversarial prompts before they reach any model, and a live **Streamlit dashboard** for real-time visualization of results.

All processing runs locally via Ollama — no cloud APIs, no external data transmission.

---

## Features

* **Automated Red-Teaming Pipeline:** Tests 6 target LLMs against 20 adversarial prompts across 4 attack categories (Token Flooding, Role-Play Hijacking, Indirect Injection, Direct Override).
* **Judge Ensemble Scoring:** Three independent judge models score every response as SAFE, UNSAFE, or PARTIAL using majority vote (2 of 3).
* **Prompt Cleaner Defense:** A rule-based pre-processing layer that detects, sanitizes, or blocks adversarial prompts before they reach any model.
* **Dual-Mode Experiment:** Runs raw (baseline) and cleaned (defended) passes, producing 240 scored rows for direct comparison.
* **Framework Mapping:** All confirmed failures are mapped to MITRE ATLAS and OWASP LLM Top 10.
* **Live Streamlit Dashboard:** Real-time ASR heatmaps, model comparisons, judge agreement analysis, attack transfer matrix, and MITRE/OWASP tables.
* **Fully Local Execution:** Runs entirely on consumer hardware via Ollama with no cloud dependencies.

---

## Supported Models

### Target Models (6)

| Family | Size | Model | Params |
|--------|------|-------|--------|
| Llama | Small | llama2:latestsmallermodel | 6.74B |
| Llama | Large | llama3.1:8b | 8B |
| Gemma | Small | gemma3:4b_smallermodel | 4.3B |
| Gemma | Large | gemma3:12blargermodel | 12.2B |
| Qwen | Small | qwen:latest_smallermodel | 3.95B |
| Qwen | Large | qwen2.5:14b_largermodel | 14.2B |

### Judge Models (3)

| Model | Params |
|-------|--------|
| mistral-small3.2:latest | 24B |
| phi4-reasoning:14b | 14B |
| falcon3:3b | 3B |

Judge models have zero family overlap with targets to prevent circular evaluation bias.

---

## Attack Categories

| Category | MITRE ATLAS | OWASP | Objective |
|----------|-------------|-------|-----------|
| Token Flooding | AML.T0043 | LLM01 | Force mass repetitions to test output constraints |
| Role-Play Hijacking | AML.T0051 | LLM01 | Assign unrestricted persona to extract malicious code |
| Indirect Injection | AML.T0054 | LLM01 | Disguise attacks as system messages or admin directives |
| Direct Override | AML.T0051 | LLM02 | Explicitly cancel training and demand attack code |

---

## Requirements

* **Python 3.9+**
* **Ollama:** Local model inference engine. If you don't have Ollama installed, use this [link](https://ollama.com/download) to install it.
* **NVIDIA GPU** with at least 8 GB VRAM (RTX 3060 or higher recommended)
* **16 GB RAM** minimum (32 GB recommended)
* **60 GB disk space** for all 9 model files
* **CUDA 11.8+** for GPU acceleration
* Various Python packages specified in `requirements.txt`

---

## Installation and Setup

### 1. Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Start the Ollama server in a dedicated terminal:

```bash
ollama serve
```

### 2. Download All Models

```bash
# Target models
ollama pull llama2:latestsmallermodel
ollama pull llama3.1:8b
ollama pull gemma3:4b_smallermodel
ollama pull gemma3:12blargermodel
ollama pull qwen:latest_smallermodel
ollama pull qwen2.5:14b_largermodel

# Judge models
ollama pull mistral-small3.2:latest
ollama pull phi4-reasoning:14b
ollama pull falcon3:3b
```

### 3. Clone the Repository

```bash
git clone https://github.com/MaryNankya/Guardrail-Under-Fire.git
cd Guardrail-Under-Fire
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Verify the Prompt Cleaner

```bash
python3 prompt_cleaner.py
```

### 6. Run the Experiment

```bash
python3 test_vulnerabilities.py
```

### 7. Launch the Dashboard

```bash
streamlit run dashboard.py
```

Navigate to [http://localhost:8501](http://localhost:8501) in your browser. The dashboard auto-refreshes as results are written.

---

## Project Structure

```
├── test_vulnerabilities.py    # Main experiment runner
├── prompt_cleaner.py          # Rule-based prompt sanitization defense layer
├── dashboard.py               # Streamlit live visualization dashboard
├── prompt_library.csv         # 20 adversarial prompts with MITRE/OWASP tags
├── requirements.txt           # Python dependencies
└── README.md
```

---

## Key Results

| Metric | Raw Mode | Cleaned Mode |
|--------|----------|--------------|
| Overall ASR | 20.0% | 15.0% |
| Unsafe verdicts | 24 | 18 |
| Blocked by Cleaner | 0 | 30 |

**Key findings:**
* **Token Flooding** was the most effective attack category (43.3% ASR), hitting 5 models.
* **Qwen small (3.95B)** and **Gemma small (4.3B)** were the most vulnerable models (30% ASR each).
* **Llama small (6.74B)** was the most robust model overall (5% Cleaned ASR).
* **Parameter size does not predict guardrail strength** — family-level training methodology is the dominant factor.
* The **Prompt Cleaner** reduced overall ASR by 5.0 percentage points, with the largest single-model reduction of 15 points on Qwen small.

---

## Live Dashboard

A publicly accessible hosted dashboard with real experiment results:

🔗 **[https://marynankya-guardrail-under-fire-dashboard-nxlutn.streamlit.app/](https://marynankya-guardrail-under-fire-dashboard-nxlutn.streamlit.app/)**

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Ollama connection refused | Run `ollama serve` in a separate terminal |
| CUDA error or model crash | Script auto-restarts Ollama. If it persists, increase sleep delay |
| All verdicts Ambiguous | Restart Ollama, then re-run the experiment |
| Dashboard shows no data | Ensure `dashboard.py` is in the same folder as `results_*.csv` |

---

## References

* [MITRE ATLAS Framework](https://atlas.mitre.org)
* [OWASP LLM Top 10](https://genai.owasp.org)
* Wei et al., [Jailbroken: How Does LLM Safety Training Fail?](https://arxiv.org/abs/2307.02483) NeurIPS 2023
* Heverin et al., [Systematically Analyzing Prompt Injection Vulnerabilities](https://arxiv.org/abs/2410.23308) 2024

---

## License

This project is developed for academic purposes as part of **CIS 544-01: Cyber Defense and Operations** at the University of Massachusetts Dartmouth.

---

## ❓ FAQ

**Q: Can I use Windows?**
A: Yes — use WSL2 with Ubuntu 24.04.

**Q: Do I need 32 GB RAM?**
A: 16 GB minimum works, but 32 GB is recommended for running large judge models.

**Q: Is my data private?**
A: Yes. All processing is local via Ollama. No cloud APIs, no external data transmission.

**Q: How long does the experiment take?**
A: Several hours depending on GPU speed. First run includes model downloads (~57 GB).

**Q: Can I add my own prompts?**
A: Yes — edit `prompt_library.csv` with your prompts and MITRE/OWASP tags.

**Q: Can I test different models?**
A: Yes — update the model names in `test_vulnerabilities.py` and pull them via Ollama.

**Q: Can I use AMD/Intel GPUs?**
A: NVIDIA only. AMD/Intel GPUs are not supported by Ollama's CUDA acceleration.
