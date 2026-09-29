<div align="center">

# 🛡️ AegisAI

### Intelligent Enterprise Threat Detection & Prevention Platform

*AI-powered, multi-layered cybersecurity — email fraud, deepfake voices, credential leaks, prompt injection, malicious attachments, and website spoofing — all in one unified platform.*

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Ollama](https://img.shields.io/badge/Ollama-LLaMA%203-black?style=flat-square)](https://ollama.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## 📖 Overview

**AegisAI** is a full-stack, microservices-based cybersecurity platform built for **Hack-O-Hire 2.0**. It detects and neutralises modern enterprise threats in real time across six distinct threat vectors, orchestrated under a single React dashboard and unified Nginx reverse proxy.

The system intercepts threats at multiple stages — *before* emails are delivered (SMTP gateway), *during* inbox monitoring, and *on-demand* through interactive analysis tools — giving security teams complete visibility and control.

---

## 🏗️ Architecture

```
                        ┌─────────────────────────────────────┐
                        │          Nginx Reverse Proxy         │
                        │              (port 80)               │
                        └────────────────┬────────────────────┘
                                         │
                  ┌──────────────────────▼──────────────────────┐
                  │          React Frontend (Vite + Tailwind)    │
                  │              http://localhost                 │
                  └──────────────────────┬──────────────────────┘
                                         │ REST API calls
          ┌──────────────────────────────▼──────────────────────────────────┐
          │                        Microservices                             │
          │                                                                  │
          │  ┌──────────────┐  ┌────────────────┐  ┌──────────────────┐    │
          │  │  DLP Gateway │  │  Email Monitor │  │ SMTP Fraud GW    │    │
          │  │   :8001      │  │    :8009       │  │  :8010 / :2525   │    │
          │  └──────────────┘  └────────────────┘  └──────────────────┘    │
          │                                                                  │
          │  ┌──────────────┐  ┌────────────────┐  ┌──────────────────┐    │
          │  │  Credential  │  │  Prompt Guard  │  │  Voice Scanner   │    │
          │  │  Scanner :8002│  │    :8005       │  │    :8006         │    │
          │  └──────────────┘  └────────────────┘  └──────────────────┘    │
          │                                                                  │
          │  ┌──────────────┐  ┌────────────────┐  ┌──────────────────┐    │
          │  │  Attachment  │  │    Website     │  │     Retrain      │    │
          │  │  Scanner :8007│  │  Spoofing :8008│  │  Scheduler :9000 │    │
          │  └──────────────┘  └────────────────┘  └──────────────────┘    │
          │                                                                  │
          │  ┌──────────────┐  ┌────────────────┐  ┌──────────────────┐    │
          │  │ Agent Sandbox│  │    Outlook     │  │   Sandbox Ollama │    │
          │  │   :8000      │  │   Plugin :3000 │  │    LLaMA 3:11434 │    │
          │  └──────────────┘  └────────────────┘  └──────────────────┘    │
          └──────────────────────────────────────────────────────────────────┘
                                         │
                  ┌──────────────────────▼──────────────────────┐
                  │         Infrastructure                        │
                  │   PostgreSQL :5432  │  Redis :6379            │
                  │         MailHog (SMTP dev) :1025/:8025        │
                  └──────────────────────────────────────────────┘
```

---

## 🔍 Modules

### 1. 📧 Email Monitoring & Phishing Detection (`email_monitoring/`)
Continuously monitors an IMAP inbox, parsing incoming emails for phishing signals using an ML classifier and LLM analysis via **Ollama (LLaMA 3)**. It stores classified emails in PostgreSQL and exposes a REST API for the dashboard.

- IMAP polling (configurable interval)
- LLM-powered threat explanation
- Email classification (phishing / spam / safe)
- Feedback-driven model retraining

### 2. 🚦 SMTP Fraud Gateway (`smtp-fraud-gateway/`)
Acts as a **pre-delivery SMTP proxy** on port `2525`. Every email passes through an **8-stage analysis pipeline** before being allowed, quarantined, or rejected:

| Stage | Detection |
|---|---|
| 1 | XGBoost ML scoring (16 features + SHAP explainability) |
| 2 | URL reputation (16-signal offline scorer) |
| 3 | Multilingual analysis: homograph, BEC, 419 scams, AI-generated content |
| 4 | Combined score → CRITICAL / HIGH / MEDIUM / LOW verdict |
| 5 | PostgreSQL audit persistence |
| 6 | Attachment microservice scan |
| 7 | LLaMA 3 authorship + manipulation tactic analysis |
| 8 | Full audit log (26 fields) |

**Thresholds:** Reject ≥ 70% · Quarantine ≥ 40% · Tag ≥ 20%

### 3. 🔑 Credential Scanner (`Credential_Scanner-main/`)
A hybrid secret-detection engine that scans any document or text for leaked credentials using a four-layer pipeline:

- **Regex patterns** — API keys, tokens, connection strings, PII (250+ patterns)
- **Entropy analysis** — Shannon entropy to catch high-randomness secrets
- **NER detection** — Named entity recognition for context-aware findings
- **LLM analysis** — Ollama-backed confirmation of ambiguous findings
- Risk scoring with deduplication and context analysis

### 4. 📎 Attachment Scanner (`attachment_scanner/`)
Deep-inspects email attachments of virtually every type for malware and suspicious content:

- **PDF** — embedded JavaScript, URI extraction, form phishing
- **Office (DOCX/XLSX)** — macro detection, suspicious links
- **PE/EXE** — import table analysis, entropy, packer detection
- **ZIP** — recursive scanning of archive contents
- **Images** — steganography detection, embedded text via OCR
- **HTML** — phishing template matching, obfuscated scripts
- **YARA rules** + **magic-byte** verification + **VirusTotal hash lookup**

### 5. 🎙️ Deepfake Voice Scanner (`fraudshield-voice/`)
Real-time audio analysis to detect AI-generated / deepfake voice calls:

- **Wav2Vec2** deep learning model for audio feature extraction
- **MFCC** (Mel-Frequency Cepstral Coefficients) feature analysis
- Random Forest classifier with calibration
- Supports WAV, MP3, FLAC, OGG, M4A, AAC, MP4, WebM
- WebSocket streaming for real-time scoring
- Feedback loop for continuous retraining

### 6. 🕸️ Website Spoofing Detection (`website_spoofing_model-main/`)
Identifies cloned / spoofed websites attempting brand impersonation:

- Visual similarity comparison (screenshot-based)
- URL analysis (homograph attacks, typosquatting)
- Cookie and certificate monitoring
- ML-powered brand similarity scoring (Flask API on port `5000`)
- Browser extension support

### 7. 🛡️ Prompt Injection Guard (`fraudshield-prompt-guard/`)
Protects AI-integrated systems from **prompt injection attacks**:

- Local fine-tuned guard model (loaded from `prompt-injection/best_model`)
- LLaMA 3 secondary verification via Ollama
- Pattern-based detection + decoded payload terminal output
- REST API on port `8005`

### 8. 🔒 DLP Gateway (`dlp-gateway/`)
A **Data Loss Prevention** gateway with policy engine:

- FastAPI on port `8001` backed by PostgreSQL + Redis
- Policy-based content inspection
- Dashboard, alerting, and reporting sub-modules
- Offline-capable (no external HuggingFace calls required)
- Browser extension integration

### 9. 🤖 Agent Sandbox (`sandbox/`)
An isolated harness for safely executing and testing AI agent payloads:

- Docker-in-Docker isolation
- LLaMA 3 via Ollama backend
- Test suite with structured JSON reports
- File upload and result inspection UI

### 10. 🔄 Retrain Scheduler (`retrain-scheduler/`)
Nightly automated model retraining orchestrator (default: **02:00 UTC**):

- Triggers retraining across Voice Scanner, Website Spoofing, and Email Monitor
- Stateful scheduler with persistent state
- HTTP health-check and status endpoints on port `9000`

### 11. 🖥️ Outlook Plugin (`outlook-plugin/`)
Microsoft Outlook add-in with dedicated analysis panes:

- **Email Pane** — Phishing risk score inline in Outlook
- **Voice Pane** — Deepfake audio check
- **Credential Pane** — Secret scanning of email body
- **Guard Pane** — Prompt injection detection
- Served over HTTPS (self-signed dev certs) on port `3000`

### 12. 🎨 Frontend Dashboard (`Frontend/`)
A premium React 18 dashboard built with **Vite**, **Tailwind CSS**, **Framer Motion**, and **Recharts**:

| Page | Purpose |
|---|---|
| Dashboard | Live threat feed, module status, risk tier grid |
| Mailbox | Email inbox with SMTP gateway verdict badges |
| Email Phishing | BERT scores, header analysis, URL scanner |
| Credential Scanner | Secrets table with entropy values |
| Attachment Analyzer | Drag-and-drop, YARA / magic-byte grid |
| Website Spoofing | URL analysis, visual clone compare |
| Deepfake Voice | Animated waveform, MFCC / Wav2Vec2 scores |
| Prompt Injection | Pattern detection, decoded payload terminal |
| Agent Sandbox | Docker config, live terminal output |
| Feedback & Retraining | Filter table, retraining queue |
| Admin Analytics | 6 Recharts charts (Line, Bar, Pie) |

---

## ⚡ Quick Start

### Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Docker Desktop | 24+ | With Compose v2 |
| Git | Any | — |
| (Optional) Node.js | 18+ | For local frontend dev only |
| (Optional) Python | 3.10+ | For local service dev only |

---

### 🐳 Docker (Recommended — Full Stack)

```bash
# 1. Clone the repository
git clone https://github.com/samarth5151/hack-o-hire-2.0.git
cd hack-o-hire-2.0

# 2. Copy and configure environment variables
cp dlp-gateway/.env.example dlp-gateway/.env
# Edit dlp-gateway/.env with your settings

# 3. Launch all services
docker compose up -d

# 4. Wait ~60 seconds for Ollama to pull LLaMA 3, then open:
#    Dashboard → http://localhost
#    MailHog   → http://localhost:8025
```

> **Note:** The first run pulls the LLaMA 3 model (~4 GB). Subsequent starts are instant.

---

### 💻 Local Dev (Windows — Frontend + Core Services)

```powershell
# Start Frontend, DLP Gateway, and Sandbox Harness in separate windows
.\start-dev.ps1
```

| Service | URL |
|---|---|
| Frontend (Vite HMR) | http://localhost:5173 |
| DLP Gateway | http://localhost:8001 |
| Sandbox Harness | http://localhost:8000 |

---

### 🧪 Testing the SMTP Fraud Gateway

```bash
# Send test emails through the fraud gateway (port 2525)
python demo_smtp.py
```

Expected: Phishing/extortion emails are **REJECTED**, legitimate emails are **ALLOWED**.

Then open **http://localhost → Mailbox**:
- **Spam / Blocked** tab — blocked phishing tests
- **Inbox** tab — allowed legitimate emails

---

## 🗂️ Port Reference

| Service | Port | Protocol |
|---|---|---|
| Nginx (Frontend + API proxy) | `80` | HTTP |
| Sandbox Harness (Agent API) | `8000` | HTTP |
| DLP Gateway | `8001` | HTTP |
| Credential Scanner | `8002` | HTTP |
| Prompt Guard | `8005` | HTTP |
| Voice Scanner | `8006` | HTTP |
| Attachment Scanner | `8007` | HTTP |
| Website Spoofing | `8008` | HTTP |
| Email Monitor | `8009` | HTTP |
| SMTP Fraud Gateway (API) | `8010` | HTTP |
| SMTP Fraud Gateway (SMTP) | `2525` | SMTP |
| Retrain Scheduler | `9000` | HTTP |
| Outlook Plugin | `3000` | HTTPS |
| Ollama (LLM runtime) | `11434` | HTTP |
| MailHog (SMTP dev UI) | `8025` | HTTP |
| MailHog (SMTP dev relay) | `1025` | SMTP |
| PostgreSQL | `5432` | TCP |
| Redis | `6379` | TCP |
| Frontend Dev Server | `5173` | HTTP |

---

## 🛠️ Tech Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 18, Vite 5, Tailwind CSS 3, Framer Motion 11, Recharts 2, React Icons |
| **API Framework** | FastAPI, Uvicorn, Pydantic v2 |
| **Email** | IMAP (imaplib), SMTP (aiosmtpd), MailHog |
| **LLM** | Ollama (LLaMA 3), local fine-tuned Wav2Vec2 / guard models |
| **ML / AI** | PyTorch, Transformers (HuggingFace), XGBoost, SHAP, scikit-learn |
| **Audio** | Wav2Vec2, librosa, MFCC feature extraction |
| **Databases** | PostgreSQL 16, Redis 7, SQLite (local fallback) |
| **Infrastructure** | Docker Compose, Nginx, Poetry, asyncpg, SQLAlchemy 2 |
| **Security tools** | YARA, python-magic, pdfplumber, python-docx, python-jose |
| **Outlook Add-in** | Office JS API, Node.js HTTPS server |

---

## 📁 Repository Structure

```
hack-o-hire-2.0/
│
├── docker-compose.yml            ← Full-stack orchestration (16 services)
├── start-dev.ps1                 ← Windows dev-mode launcher
├── demo_smtp.py                  ← SMTP gateway test harness
│
├── Frontend/                     ← React 18 dashboard (Vite + Tailwind)
├── dlp-gateway/                  ← DLP policy engine (FastAPI + PostgreSQL)
├── email_monitoring/             ← IMAP monitor + LLM email classifier
├── smtp-fraud-gateway/           ← Pre-delivery SMTP fraud interception
├── attachment_scanner/           ← Deep attachment analysis (PDF/PE/Office/YARA)
├── Credential_Scanner-main/      ← Secret detection (regex + entropy + NER + LLM)
├── fraudshield-voice/            ← Deepfake voice detection (Wav2Vec2)
├── fraudshield-prompt-guard/     ← Prompt injection detection
├── website_spoofing_model-main/  ← Website clone / spoofing detection
├── sandbox/                      ← AI agent harness & test suite
├── retrain-scheduler/            ← Nightly automated model retraining
├── outlook-plugin/               ← Microsoft Outlook add-in
├── prompt-injection/             ← Guard model weights
├── nginx/                        ← Nginx reverse proxy config
└── SMTP_GATEWAY_TESTING_GUIDE.md ← Detailed SMTP testing walkthrough
```

---

## 🔧 Configuration

Key environment variables (see `dlp-gateway/.env.example` for full list):

```env
# Database
POSTGRES_URL=postgresql+asyncpg://dlp:dlp@postgres:5432/dlp
REDIS_URL=redis://redis:6379

# Ollama (LLM)
OLLAMA_URL=http://sandbox-ollama:11434

# SMTP Gateway Thresholds
REJECT_THRESHOLD=0.70
QUARANTINE_THRESHOLD=0.40
TAG_THRESHOLD=0.20

# Email Monitoring (IMAP)
IMAP_SERVER=imap.gmail.com
IMAP_PORT=993
IMAP_USER=your-email@gmail.com
IMAP_PASSWORD=your-app-password
```

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Built with ❤️ for **Hack-O-Hire 2.0**

</div>
