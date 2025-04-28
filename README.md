# Connected Vehicle Solana
Real-Time Vehicle Trust Management with SUMO Simulation and Solana Blockchain

---

## 📚 Overview

This project simulates connected vehicles using the SUMO traffic simulator, evaluates their trust scores in real-time, manages data with a Flask backend, and securely stores key information on the Solana blockchain via smart contracts.

The system includes:
- **Real-time vehicle simulation** using SUMO
- **Trust score calculation** and malicious behavior detection
- **Smart contracts** on Solana blockchain
- **Monitoring and logging** of vehicle behaviors and transactions
- **Dynamic frontend to interact with vehicles and platoons**

---

## 📦 Project Structure

| Folder | Description |
|:-------|:------------|
| `backend/` | Flask API server + SUMO interface + blockchain integration |
| `frontend/` | React frontend for live vehicle tracking and node management |
| `sumo/` | SUMO network and route configuration files |
| `solana-smart-contract/` | Solana smart contracts (vehicle node, platoon manager, etc.) |
| `monitoring_results/` | Output graphs and monitoring data |

---

## 🛠️ Requirements

- **Python 3.9+** (for backend)
- **Node.js 18+** (for frontend)
- **SUMO Traffic Simulator** (version 1.8+ recommended)
- **Solana CLI + Anchor CLI** (for deploying smart contracts)
- **Conda** (optional, for environment management)

Python packages:
- Flask
- Flask-Cors
- traci
- numpy
- utm
- anchorpy
- solders
- requests

(Installable via `environment.yml`.)

---

## ⚙️ Setup Guide

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/connected-vehicle-solana.git
cd connected-vehicle-solana
```

### 2. Backend Setup (Flask + SUMO)

✅ Create and activate environment:

```bash
conda env create -f environment.yml
conda activate your-env-name
```

✅ Install SUMO separately:
```bash
# Ubuntu
sudo apt install sumo sumo-tools

# MacOS (with brew)
brew install sumo
```

✅ Run SUMO simulation manually:

```bash
sumo --remote-port 5001 -c sumo/osm.sumocfg
```

> This command starts SUMO and opens port 5001 for live interaction.

✅ Start the backend Flask server:

```bash
python3 backend/sumo_realtime.py
```

---

### 3. Frontend Setup (React App)

✅ Go into the frontend folder:

```bash
cd frontend
npm install
npm start
```

✅ Your frontend will open at:

```
http://localhost:3000
```

### 🌐 Frontend Features

- Displays real-time vehicle movement on a live map
- Each vehicle is clickable
- Clicking a vehicle opens its **Node View** page, showing:
  - Wallet address
  - Trust score
  - Behavior status
  - Ability to **submit updated trust score** to the blockchain
  - Ability to **request to join a platoon** dynamically
- Platoon Managers can monitor and approve vehicle requests inside the **Platoon Dashboard**

**All interactions are dynamic** and based on real-time simulation data.

---

### 4. Blockchain Setup (Solana Smart Contracts)

✅ Install Solana CLI:

```bash
sh -c "$(curl -sSfL https://release.solana.com/v1.14.17/install)"
```

✅ Install Anchor CLI:

```bash
cargo install --git https://github.com/coral-xyz/anchor anchor-cli --locked
```

✅ Deploy smart contracts:

```bash
cd solana-smart-contract
anchor build
anchor deploy
```

> (Make sure you are connected to Devnet.)

---

## 🚗 How to Run the Monitoring Script

✅ Start real-time vehicle monitoring and data collection:

```bash
python3 backend/vehicle_monitor.py --duration 6000 --update-interval 15 --vehicle-prefix veh
```

Where:

| Parameter | Meaning |
|:----------|:--------|
| `--duration 6000` | Total simulation duration in seconds |
| `--update-interval 15` | How often (in seconds) to update vehicle trust scores |
| `--vehicle-prefix veh` | Prefix used for vehicle IDs in SUMO |

### 🔄 Automatic Monitoring Behavior

- Vehicle trust scores are updated automatically.
- Behavior evaluation and ZKP generation are handled in the backend.
- Vehicles automatically request to join platoons if eligible.
- Smart contracts are updated in real-time without user intervention.
- Monitoring results (plots and JSON data) are saved into `monitoring_results/`.

> **User does not need to manually click anything for monitoring to happen.**

---

## 📊 Monitoring Output Examples

- Latency vs Load graphs
- Trust Score Evolution
- Malicious Vehicle Detection Matrix
- Solana Transaction Costs
- Platoon Membership Changes

All plots are automatically generated after simulation ends!

---

## 📉 Useful Commands Summary

| Action | Command |
|:-------|:--------|
| Run SUMO | `sumo --remote-port 5001 -c sumo/osm.sumocfg` |
| Start backend Flask server | `python3 backend/sumo_realtime.py` |
| Start frontend React app | `npm start` inside `frontend/` |
| Deploy smart contracts | `anchor deploy` inside `solana-smart-contract/` |
| Run monitoring script | `python3 backend/vehicle_monitor.py --duration 6000 --update-interval 15 --vehicle-prefix veh` |

---

