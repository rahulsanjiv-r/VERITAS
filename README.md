# VERITAS

**V**erified **E**PR **R**ecycling with **I**ntegrity **T**amper-proof **A**rrival **S**ignatures

> *Latin for "truth" — because a certificate is only as honest as the physical reality it represents.*

VERITAS is an open-source hardware and software system that eliminates fraudulent Extended Producer Responsibility (EPR) recycling certificates. By deploying an ESP32 gate pod at the facility that weighs, photographs, and cryptographically signs every truck arrival, VERITAS ensures absolute integrity. The backend independently re-verifies the signature before minting any certificate. No physical record = no certificate, period.

---

## Why I Created This Project

India's EPR (Extended Producer Responsibility) framework requires plastic, e-waste, and metal producers to prove their waste was collected and recycled. However, the current certificate system is easily gamed. Bad actors use ghost facilities, inflated weights, and circular trucking (where the same truck loops around multiple times) to generate fraudulent certificates worth real money. 

Fake EPR certificates directly harm the environment by creating a facade of recycling while plastic and e-waste continue to pile up. I created VERITAS to fix this systemic issue at the physical gate. By ensuring every certificate is tied to a cryptographically verified, tamper-proof physical event, we can restore trust in the EPR system. 

**Why Open Source?**
This tool is most effective when recycling facilities, regulators, and developers everywhere can deploy, audit, and improve it. The code serves as the specification. By open-sourcing VERITAS, the community can fork it, deploy it, and enhance it to protect our environment from fraud.

---

## How It Works

```
Truck arrives → ESP32 weighs it → Camera captures JPEG → SHA-256 hash computed
     ↓
Canonical record: weight|facility|timestamp|photo_hash|device_id
     ↓
Ed25519 signature (device private key, stored in flash)
     ↓
POST /arrivals → Backend recomputes canonical hash + verifies signature
     ↓
Fraud checks pass → Atomic mint → Merkle ledger updated → Certificate issued
```

## Detailed Installation Instructions

Follow these instructions to set up the VERITAS ecosystem on your local machine or server.

### Prerequisites
- **Python 3.11+** for the backend
- **Node.js 18+** (optional, for advanced dashboard/mobile tweaks)
- **Docker & Docker Compose** (for easy deployment)
- **Git**

### 1. Local Backend Setup (Manual)

The backend is a FastAPI application that handles cryptography, fraud checks, database operations, and the ledger.

```bash
# Clone the repository
git clone https://github.com/rahulsanjiv-r/VERITAS.git
cd VERITAS

# Create and activate a virtual environment
python -m venv venv
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install all required dependencies
pip install -r backend/requirements.txt
pip install -r requirements-dev.txt

# Set up required environment variables
export VERITAS_JWT_SECRET="generate-a-secure-32-character-secret-here"
export VERITAS_DB_PATH="veritas.db"

# Run the FastAPI server
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```
- **Backend API**: `http://localhost:8000`
- **API Documentation (Swagger UI)**: `http://localhost:8000/docs`

### 2. Dashboard and Mobile PWA Setup

The dashboard and mobile PWA are static interfaces that communicate with the backend. If you are running the backend via `uvicorn`, these are served automatically if properly configured in the FastAPI static mounts.

- **Dashboard**: Open `http://localhost:8000/dashboard/` in your browser. (Alternatively, open `dashboard/index.html` directly if CORS allows).
- **Mobile PWA**: Open `http://localhost:8000/mobile/` to access the field audit app.

### 3. Running the Test Suite

VERITAS includes 147 rigorous tests for cryptographic round-trips, fraud checks, concurrency, auth, and computer vision.

```bash
# Ensure your virtual environment is active and dev dependencies are installed
pip install -r requirements-dev.txt

# Run all tests using pytest
pytest tests/ -v
```

### 4. Simulating a Device (No Hardware Required)

You don't need the physical ESP32 pod to test the system. You can simulate an arrival event, a forged signature, and an over-capacity arrival.

```bash
# Run the simulator script against your local backend
python scripts/simulate_pod.py --url http://localhost:8000 --secret "generate-a-secure-32-character-secret-here"
```

### 5. Docker Deployment (Recommended for Production/Servers)

The easiest way to run the entire software stack is via Docker Compose.

```bash
# Make sure you are in the project root
cd veritas

# Set your JWT secret in the docker-compose.yml or as an environment variable
export VERITAS_JWT_SECRET="your-production-secret-here"

# Build and spin up the containers
docker-compose -f ops/docker-compose.yml up --build -d

# Check the logs to ensure everything is running smoothly
docker-compose -f ops/docker-compose.yml logs -f
```

### 6. Hardware Setup (ESP32 Gate Pod)

For the physical deployment, you will need the following components:
- **ESP32** (Any variant with camera support, e.g., ESP32-CAM)
- **HX711** load cell amplifier (for the scale)
- **u-blox NEO-6M** GPS module
- **WolfSSL Ed25519** (bundled in ESP32 Arduino core ≥2.0)

**Flashing the Firmware:**
1. Open the Arduino IDE.
2. Load the sketch located at `firmware/veritas_pod/veritas_pod.ino`.
3. Install the required libraries (e.g., HX711, TinyGPS++).
4. Configure your WiFi credentials and backend endpoint in the sketch.
5. Compile and upload to your ESP32 board.

*Note: Firmware is fully written and syntax-checked. Physical bench-testing with real components is required before production deployment.*

---

## How to Use VERITAS

### For Facility Operators
1. **Onboard your facility**: Register your facility details and capacity limits in the system.
2. **Weigh-In**: When a truck arrives, the ESP32 gate pod automatically takes a photo, records the weight, and generates a cryptographically signed payload.
3. **Dashboard Monitoring**: Log into the web dashboard to see real-time arrivals.
4. **Mint Certificates**: Once an arrival passes all server-side fraud checks (e.g., capacity ceiling, circular-trucking), a certificate is atomically minted and added to the Merkle ledger.

### For Regulators and Auditors
1. **Mobile Audit App**: Field auditors can use the Mobile PWA offline or online to verify certificates on-site.
2. **Scan & Verify**: Scan a certificate's QR code to pull its Merkle proof and verify the underlying signature and photo.
3. **Audit Exports**: Generate CPCB-compliant JSON and CSV exports directly from the backend to review facility compliance and flagged fraud attempts.

---

## Key Features

- **Cryptographic signing** — Ed25519 signature on every arrival (WolfSSL on ESP32)
- **Server-side hash recompute** — backend never trusts the submitted hash; always recomputes
- **Atomic minting** — single `UPDATE WHERE used=0` prevents double-spend under concurrency
- **Merkle ledger** — every certificate is part of a tamper-evident hash chain
- **Fraud detection** — capacity ceiling, ghost facility, and GPS-backed circular trucking checks
- **Computer Vision** — lightweight image analysis (color histograms, dHash) for waste category verification

---

## Cryptographic Invariants

These invariants are non-negotiable and strictly tested in the CI pipeline:
1. **Ed25519 signature** on every arrival — never skipped.
2. **Server-side canonical hash recompute** — never trust submitted hash.
3. **Atomic mint** — race-condition-proof database updates.
4. **Fraud checks are real** — fail-closed, never stubbed.
5. **Merkle proof** on every certificate.
6. **WAL mode** on SQLite — durable writes.
7. **Audit log** — every action is permanently logged.
8. **Tenant isolation** — operators can only see their own facility.

---

## Contributing

Contributions are welcome! Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a PR. Bug fixes, new fraud detection algorithms, better CV models, and hardware integrations are especially welcome. Every PR must include tests.

## License

This project is licensed under a modified MIT License. **The code belongs to Rahul Sanjiv (rahulsanjiv-r).** 

While it is open for personal and educational use, **commercial use requires explicit permission**. See the [LICENSE](LICENSE) file for more details.

---

*Note: I designed and created the core agent skills and project templates for VERITAS. I used the Antigravity AI assistant to help speed up the development process, run debugging, and check for API leaks.*
