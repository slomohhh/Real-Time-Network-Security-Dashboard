# Flotrusion

**Real-time network security monitoring dashboard.**  
Captures live packet traffic, classifies protocols, detects anomalies, and surfaces alerts — all through a clean browser interface that updates every second.

Built by **Mohammad Khan** 

---

## What it does

Flotrusion ingests raw network packets (or simulated traffic in demo mode), runs them through a detection engine, and exposes the results through a REST API consumed by a React dashboard.

Three anomaly detectors run on every tick:

| Detector | Trigger | Severity |
|---|---|---|
| Port scan | ≥15 unique destination ports from one IP within 10s | Critical |
| SYN flood | ≥200 SYN packets with <10% handshake completion within 5s | Critical |
| UDP spike | UDP rate exceeds 3× the rolling EMA baseline | Warning |

New devices are detected and logged as informational alerts on first packet observation.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│  React Frontend  (Vite + TypeScript + Recharts)  │
│  Polls /api/v1/* every 1–3s                      │
└────────────────────┬────────────────────────────┘
                     │ HTTP / JSON
┌────────────────────▼────────────────────────────┐
│  FastAPI Backend                                 │
│  ┌──────────────────────────────────────────┐   │
│  │  PacketCollector (asyncio background task)│   │
│  │  • Scapy live capture  OR                │   │
│  │  • Deterministic simulation              │   │
│  └──────────┬───────────────────────────────┘   │
│             │ per-second tick                    │
│  ┌──────────▼───────────────────────────────┐   │
│  │  AnomalyDetector                         │   │
│  │  detect_port_scan()                      │   │
│  │  detect_syn_flood()                      │   │
│  │  detect_udp_spike()                      │   │
│  │  detect_new_devices()                    │   │
│  └──────────────────────────────────────────┘   │
│  In-memory ring buffer (60s history)             │
└─────────────────────────────────────────────────┘
```

**Backend:** Python 3.12 · FastAPI · Pydantic v2 · Scapy · asyncio  
**Frontend:** React 18 · TypeScript · Vite · Recharts · CSS Modules

No database dependency — history lives in a deque ring buffer in memory. Swap in PostgreSQL or SQLite for persistence (the schema maps directly from `TrafficSnapshot` and `Alert` models).

---

## Project structure

```
flotrusion/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app, lifespan, middleware
│   │   ├── api/__init__.py      # Route handlers
│   │   ├── core/
│   │   │   ├── config.py        # Settings (pydantic-settings, .env)
│   │   │   └── collector.py     # Background packet collector
│   │   ├── models/
│   │   │   └── schemas.py       # Pydantic domain + response models
│   │   └── services/
│   │       └── detector.py      # Anomaly detection engine
│   ├── tests/
│   │   └── test_detector.py     # Unit tests for all detectors
│   ├── requirements.txt
│   └── .env.example
│
└── frontend/
    ├── src/
    │   ├── components/
    │   │   ├── alerts/          # AlertFeed
    │   │   ├── charts/          # TrafficChart, ProtocolChart
    │   │   ├── dashboard/       # StatCard, TopTalkersTable
    │   │   └── layout/          # TopBar, Panel
    │   ├── hooks/
    │   │   └── usePolling.ts    # Generic poll hook + resource hooks
    │   ├── pages/
    │   │   └── Dashboard.tsx    # Main page, composes all panels
    │   ├── services/
    │   │   └── api.ts           # All fetch calls in one place
    │   ├── types/
    │   │   └── api.ts           # TypeScript mirror of backend schemas
    │   └── utils/
    │       └── format.ts        # formatPackets, formatBytes, relativeTime
    ├── package.json
    └── vite.config.ts
```

---

## Getting started

### Prerequisites

- Python 3.12+
- Node.js 20+
- (Optional) root/admin privileges for live packet capture

### Backend

```bash
cd backend

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env — SIMULATION_MODE=true by default (no root needed)

# Run
uvicorn app.main:app --reload
# API available at http://localhost:8000
# Docs at http://localhost:8000/api/docs
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# Dashboard at http://localhost:5173
```

### Run tests

```bash
cd backend
pytest tests/ -v
```

---

## Live capture mode

To capture real traffic, disable simulation mode and set your network interface:

```env
SIMULATION_MODE=false
NETWORK_INTERFACE=eth0   # macOS: en0
```

Live capture requires Scapy and elevated privileges:

```bash
# Linux
sudo uvicorn app.main:app

# macOS
sudo uvicorn app.main:app

# Windows (run terminal as Administrator)
uvicorn app.main:app
```

Find your interface name:

```bash
# Linux / macOS
ip link show        # or: ifconfig

# Windows
ipconfig
```

---

## Configuration

All thresholds are configurable via environment variables — no code changes needed.

| Variable | Default | Description |
|---|---|---|
| `SIMULATION_MODE` | `true` | Use simulated traffic instead of live capture |
| `NETWORK_INTERFACE` | `eth0` | Interface for live capture |
| `PORT_SCAN_THRESHOLD` | `15` | Unique ports per IP per window to trigger alert |
| `PORT_SCAN_WINDOW_SECS` | `10` | Detection window in seconds |
| `SYN_FLOOD_THRESHOLD` | `200` | SYN packets per IP per window |
| `SYN_FLOOD_WINDOW_SECS` | `5` | Detection window in seconds |
| `UDP_SPIKE_MULTIPLIER` | `3.0` | Multiplier over EMA baseline to trigger alert |
| `TRAFFIC_HISTORY_SECS` | `60` | Seconds of traffic kept in memory |
| `MAX_ALERTS` | `100` | Maximum alerts retained in memory |

---

## API reference

All endpoints return JSON. Base path: `/api/v1`

| Method | Path | Description |
|---|---|---|
| `GET` | `/traffic` | 60-second traffic history + current snapshot |
| `GET` | `/alerts?limit=20` | Recent anomaly alerts, newest first |
| `GET` | `/top-talkers?n=10` | Top N source IPs by packet count |
| `GET` | `/stats` | Current pps, alert count, flagged IPs, uptime |
| `GET` | `/health` | Health check |

Interactive docs: `http://localhost:8000/api/docs`

---

## Deployment

### Backend → Render (free tier)

1. Push the `backend/` directory to a GitHub repo
2. Create a new **Web Service** on [render.com](https://render.com)
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Add environment variables in the Render dashboard

### Frontend → Vercel

```bash
cd frontend
npm run build
# Deploy the dist/ folder to Vercel, Netlify, or GitHub Pages
```

Set `VITE_API_BASE` in your Vercel environment variables to point at your Render backend URL.

---

## Design decisions

**Why asyncio for the collector?**  
Scapy's `AsyncSniffer` runs in a thread pool, so the main event loop stays unblocked. The per-second tick runs as a `Task`, ensuring API responses are never delayed by packet processing.

**Why pure functions for detectors?**  
Each detector (`detect_port_scan`, `detect_syn_flood`, etc.) is a plain function with no side effects. This makes them trivially unit-testable and easy to swap or extend without touching the collector logic.

**Why a ring buffer instead of a database?**  
For a 60-second monitoring window, a `deque(maxlen=60)` is zero-latency and zero-dependency. The tradeoff is no persistence across restarts — acceptable for a real-time dashboard, replaceable with SQLite or Postgres when persistence matters.

**Why CSS Modules over Tailwind?**  
Explicit, scoped class names make the component styling self-documenting and eliminate purge/JIT configuration complexity. Every style rule has exactly one owner.

---

## Skills demonstrated

| Area | Evidence |
|---|---|
| Systems / networking | Raw packet classification (TCP/UDP/ICMP), BPF filters, SYN flag analysis, port scan heuristics |
| Backend engineering | Async Python, FastAPI lifespan management, Pydantic v2 schema design, EMA-based baselining |
| Frontend engineering | React 18, strict TypeScript, generic poll hook, Recharts, CSS Modules, responsive layout |
| Software design | Layered architecture, pure-function detectors, single-responsibility components |
| Testing | Pytest unit tests for each detector, edge-case coverage (zero baseline, deduplication) |
| DevOps | Environment-driven config, Render + Vercel deployment path, GZip middleware |

---

## Roadmap

- [ ] WebSocket streaming (replace polling)
- [ ] SQLite/Postgres persistence for alert history
- [ ] IP geolocation enrichment
- [ ] Alert resolution / acknowledgment workflow
- [ ] Configurable alert rules via UI
- [ ] Docker Compose setup

---

## Author

**Mohammad Khan**  

---

## License

MIT — see [LICENSE](LICENSE) for details.
