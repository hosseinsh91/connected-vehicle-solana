"""
SUMO Realtime API - V1.0
-------------------------
This module provides a Flask API for the integration between SUMO (Simulation of Urban MObility) 
and a blockchain system (Solana) for vehicle trust management, verification, and platoon formation.

The system manages vehicle trust scores, detects malicious behavior, and controls platoon membership
based on zero-knowledge proofs (ZKP) and trust verification.

Author: Your Name
License: MIT
"""

import random
import subprocess
import time
import utm
import numpy as np
import os
import json
import asyncio
import traci
from flask import Flask, jsonify, request
from flask_cors import CORS
from solders.keypair import Keypair
from solana.rpc.api import Client
from solana.rpc.async_api import AsyncClient
from anchorpy import Provider, Program, Wallet, Idl, Context
from base58 import b58decode
from solders.pubkey import Pubkey as PublicKey
import hashlib
from datetime import datetime, timezone
import csv
import requests

# =============================================================================
# CONFIGURATION
# =============================================================================

# SUMO Configuration
SUMO_BINARY = "sumo"
SUMO_CONFIG = "sumo/osm.sumocfg"
SUMO_PORT = 5001

# Solana Configuration
SOLANA_RPC_URL = "https://api.devnet.solana.com"
solana_client = Client(SOLANA_RPC_URL)  # Fixed typo from original 'sulana_client'

# Wallet Directories
WALLET_DIR = "backend/vehicle_wallets"
RSU_WALLET_DIR = "backend/rsu_wallets"

# Coordinate conversion constants
NET_OFFSET_X = -578111.62
NET_OFFSET_Y = -5618666.24
UTM_ZONE = 30
IS_NORTHERN = True

# Program IDs (Blockchain)
VEHICLE_PROGRAM_ID = PublicKey.from_string("")
PLATOON_PROGRAM_ID = PublicKey.from_string("")
SYSTEM_PROGRAM_ID = PublicKey.from_bytes(b58decode("11111111111111111111111111111111"))
# Note: GLOBAL_REWARD_PROGRAM_ID is referenced but not defined here

# Load Smart Contract IDLs (Interface Definition Language)
with open("solana-smart-contract/target/idl/vehicle_node_chain.json", "r") as f:
    vehicle_idl = Idl.from_json(f.read())
with open("solana-smart-contract/target/idl/platoon_manager.json", "r") as f:
    platoon_idl = Idl.from_json(f.read())

# RSUs (Road-Side Units) information
rsus = {
    "RSU_1": {"lat": 50.720128, "lon": -1.880847, "platoons": {}},
    "RSU_2": {"lat": 50.723128, "lon": -1.878847, "platoons": {}},
}

# Simulation parameters
MALICIOUS_RATIO = 0.25  # 25% of vehicles will eventually become malicious

# =============================================================================
# GLOBAL STATE STORES
# =============================================================================
vehicle_types = {}         # Maps vehicle_id -> "normal" or "malicious"
vehicle_registry = {}      # General vehicle registry
vehicle_metadata = {}      # Stores metadata about vehicles
malicious_flags = {}       # Tracks which vehicles are flagged as malicious
vehicle_trust_scores = {}  # Stores trust score history for vehicles
zkp_logs = {}              # Logs for zero-knowledge proofs
platoon_assignments = {}   # Maps vehicles to platoons
vehicle_logs = {}          # Logs for vehicle data (for CSV export)

# =============================================================================
# FLASK APP SETUP
# =============================================================================
app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def convert_sumo_to_gps(x, y):
    """
    Convert SUMO coordinates to GPS coordinates (latitude/longitude).
    
    Args:
        x (float): SUMO x-coordinate
        y (float): SUMO y-coordinate
        
    Returns:
        tuple: (latitude, longitude)
    """
    easting = x - NET_OFFSET_X
    northing = y - NET_OFFSET_Y
    lat, lon = utm.to_latlon(easting, northing, UTM_ZONE, northern=IS_NORTHERN)
    return lat, lon

def classify_vehicle(vehicle_id):
    """
    Deterministically classify a vehicle as normal or malicious
    based on a hash of its ID. This ensures consistent classification
    across restarts without revealing the classification in logs.
    
    Args:
        vehicle_id (str): Unique identifier for the vehicle
        
    Returns:
        str: "normal" or "malicious"
    """
    if vehicle_id in vehicle_types:
        return vehicle_types[vehicle_id]
    
    # Use a hash of the vehicle_id to deterministically assign type
    # This ensures consistent classification across restarts
    hashed = hashlib.sha256(vehicle_id.encode()).digest()
    # Convert first byte to an integer and check if below threshold
    is_malicious = (hashed[0] / 255.0) < MALICIOUS_RATIO
    vehicle_type = "malicious" if is_malicious else "normal"
    
    # Store for future reference
    vehicle_types[vehicle_id] = vehicle_type
    
    # Secret log that doesn't reveal classification to regular logs
    with open("vehicle_classification.log", "a") as f:
        f.write(f"{vehicle_id},{vehicle_type}\n")
    
    return vehicle_type

def generate_wallet(vehicle_id):
    """
    Generate or retrieve a wallet for a vehicle.
    
    Args:
        vehicle_id (str): Unique identifier for the vehicle
        
    Returns:
        str: Path to the wallet file
    """
    if not os.path.exists(WALLET_DIR):
        os.makedirs(WALLET_DIR)
    wallet_path = f"{WALLET_DIR}/{vehicle_id}_keypair.json"
    if os.path.exists(wallet_path):
        return wallet_path
    account = Keypair()
    with open(wallet_path, "w") as f:
        json.dump(list(account.to_bytes()), f)
    return wallet_path

def generate_rsu_wallet(rsu_id):
    """
    Generate or retrieve a wallet for a Road-Side Unit (RSU).
    
    Args:
        rsu_id (str): Unique identifier for the RSU
        
    Returns:
        tuple: (keypair, wallet_path, is_newly_created)
    """
    if not os.path.exists(RSU_WALLET_DIR):
        os.makedirs(RSU_WALLET_DIR)
    wallet_path = f"{RSU_WALLET_DIR}/{rsu_id}_keypair.json"
    if os.path.exists(wallet_path):
        with open(wallet_path, "r") as f:
            secret = json.load(f)
        kp = Keypair.from_bytes(bytes(secret))
        return kp, wallet_path, False
    else:
        kp = Keypair()
        with open(wallet_path, "w") as f:
            json.dump(list(kp.to_bytes()), f)
        return kp, wallet_path, True

# Initialize RSU wallets
for rsu_id in rsus:
    kp, wallet_path, created = generate_rsu_wallet(rsu_id)
    rsus[rsu_id]["wallet"] = str(kp.pubkey())
    rsus[rsu_id]["wallet_obj"] = kp
    print(f"{'🆕' if created else '🔁'} Wallet {'created' if created else 'loaded'} for {rsu_id}: {kp.pubkey()}")

def calculate_trust_score(vehicle_id, behavior):
    """
    Calculate trust score with specific volatility patterns for normal and malicious vehicles.
    
    This function models different trust score evolution patterns:
    - Normal vehicles maintain stable scores between 75-85
    - Malicious vehicles act normal until joining a platoon, then exhibit
      suspicious behavior after a delay
    
    Args:
        vehicle_id (str): Unique identifier for the vehicle
        behavior (str): Current behavior of the vehicle ('safe', 'aggressive', etc.)
        
    Returns:
        float: Calculated trust score (0-100)
    """
    # Base scores for different behaviors
    score_map = {'safe': 100, 'aggressive': 60, 'speeding': 50, 'frequent_lane_change': 70}
    base_score = score_map.get(behavior, 50)

    # Ensure metadata is initialized
    vehicle_metadata.setdefault(vehicle_id, {})
    vehicle_metadata[vehicle_id].setdefault("platoon_status", "not_joined")
    vehicle_metadata[vehicle_id].setdefault("evolution_stage", "initial")
    vehicle_metadata[vehicle_id].setdefault("join_history", [])
    vehicle_metadata[vehicle_id].setdefault("leave_queued", False)
    vehicle_metadata[vehicle_id].setdefault("access_flags", {
        "can_share_data": False,
        "can_join_platoon": False
    })
    vehicle_metadata[vehicle_id].setdefault("reward_tokens", 0.0)
    vehicle_metadata[vehicle_id].setdefault("malicious_revealed", False)
    vehicle_metadata[vehicle_id].setdefault("tagged_malicious", False)

    # Get platoon status and evolution stage
    current_status = vehicle_metadata[vehicle_id]["platoon_status"]
    evolution_stage = vehicle_metadata[vehicle_id]["evolution_stage"]

    # Check if vehicle is classified as malicious
    vehicle_type = classify_vehicle(vehicle_id)

    # Track platoon join time
    join_time = None
    if current_status.startswith("joined_"):
        join_time = vehicle_metadata[vehicle_id].get("join_timestamp")
        if join_time is None:
            join_time = time.time()
            vehicle_metadata[vehicle_id]["join_timestamp"] = join_time

    # Calculate time in platoon
    time_in_platoon = 0
    if join_time:
        time_in_platoon = time.time() - join_time

    # Initialize trust score record
    if vehicle_id not in vehicle_trust_scores:
        # Start with scores that can join the platoon (>=80)
        initial_score = random.uniform(75, 85)
        vehicle_trust_scores[vehicle_id] = {
            'trust_score': initial_score,
            'count': 1,
            'scores': [initial_score],
            'previous_score': initial_score,
            'last_score_time': time.time(),
            'change_rate': 0  # Track rate of change
        }

    # Retrieve previous trust score
    prev_score = vehicle_trust_scores[vehicle_id].get('trust_score', 82)
    last_score_time = vehicle_trust_scores[vehicle_id].get('last_score_time', time.time())
    time_since_last_score = time.time() - last_score_time

    # === Raw Score Calculation Based on Vehicle Type and Status ===
    
    # Normal vehicles maintain stable scores between 75-85
    if vehicle_type == "normal":
        # Normal vehicles have small changes, staying mostly between 75-85
        if prev_score < 77:
            drift = random.uniform(0, 2.0)  # Upward drift when score is low
        elif prev_score > 83:
            drift = random.uniform(-2.0, 0)  # Downward drift when score is high
        else:
            drift = random.uniform(-1.5, 1.5)  # Small movements in the middle range
            
        raw_score = prev_score + drift
        
    # Malicious vehicles
    else:
        if not current_status.startswith("joined_"):
            # Act normal until joining platoon
            if prev_score < 80:
                drift = random.uniform(0, 2.0)  # Try to get above threshold
            elif prev_score > 90:
                drift = random.uniform(-2.0, 0)  # Don't look too perfect
            else:
                drift = random.uniform(-1.0, 1.0)  # Look stable
            raw_score = prev_score + drift
            
        else:
            # After joining platoon
            if time_in_platoon < 10:
                # Act normal for the first 10 seconds
                if prev_score < 80:
                    drift = random.uniform(0, 1.0)
                elif prev_score > 90:
                    drift = random.uniform(-1.0, 0)
                else:
                    drift = random.uniform(-1.0, 1.0)
                raw_score = prev_score + drift
                
            else:
                # After 10 seconds, start showing malicious behavior
                if not vehicle_metadata[vehicle_id]["malicious_revealed"]:
                    vehicle_metadata[vehicle_id]["malicious_revealed"] = True
                    print(f"🔴 Malicious vehicle {vehicle_id} begins showing its true nature")
                
                # Big changes within short time periods
                change_intensity = random.random()
                
                if change_intensity < 0.7:  # 70% chance of significant negative change
                    # Calculate a drop that will get noticed (5+ points) but not too dramatic all at once
                    drop_amount = random.uniform(5.0, 8.0)
                    raw_score = prev_score - drop_amount
                    print(f"🔴 Malicious vehicle {vehicle_id} showing suspicious drop of {drop_amount:.2f} points")
                elif change_intensity < 0.9:  # 20% chance of small recovery (to be unpredictable)
                    raw_score = prev_score + random.uniform(1.0, 3.0)
                    print(f"🔴 Malicious vehicle {vehicle_id} temporarily recovering score")
                else:  # 10% chance of staying roughly the same
                    raw_score = prev_score + random.uniform(-1.0, 1.0)
    
    # Clamp raw score
    raw_score = max(0, min(100, raw_score))

    # Update score history
    existing_data = vehicle_trust_scores[vehicle_id]
    existing_data['scores'].append(raw_score)
    if len(existing_data['scores']) > 5:
        existing_data['scores'] = existing_data['scores'][-5:]
    
    # Calculate rate of change (points per second)
    if time_since_last_score > 0:
        change_rate = abs(raw_score - prev_score) / time_since_last_score
        existing_data['change_rate'] = change_rate
        
        # Tag as malicious if change rate is very high (more than 5 points in short time)
        if change_rate > 6.0 and not vehicle_metadata[vehicle_id]["tagged_malicious"]:
            vehicle_metadata[vehicle_id]["tagged_malicious"] = True
            print(f"⚠️ Vehicle {vehicle_id} TAGGED AS MALICIOUS due to change rate of {change_rate:.2f} points/sec")

    # === Averaging - applied differently based on vehicle type ===
    if vehicle_type == "normal":
        # Normal vehicles get moderate smoothing
        avg_score = prev_score * 0.6 + raw_score * 0.4
    else:
        if not current_status.startswith("joined_") or time_in_platoon < 10:
            # Before joining or during initial period, smooth heavily to appear normal
            avg_score = prev_score * 0.7 + raw_score * 0.3
        else:
            # After revealing malicious nature, reduce smoothing to show true pattern
            avg_score = prev_score * 0.2 + raw_score * 0.7
            
            # For malicious vehicles, gradually trend downward over time
            if time_in_platoon > 10:
                avg_score = max(0, avg_score - random.uniform(0, 1.5))  # Additional gradual decline

    # Final updates
    existing_data['previous_score'] = prev_score
    existing_data['trust_score'] = avg_score
    existing_data['count'] += 1
    existing_data['last_score_time'] = time.time()

    # Debug logging
    if abs(raw_score - prev_score) > 2 or (vehicle_type == "malicious" and current_status.startswith("joined_") and time_in_platoon > 10):
        print(f"{'🟢' if vehicle_type == 'normal' else '🔴'} Score for {vehicle_id} ({vehicle_type}): {prev_score:.2f} → {raw_score:.2f} (raw)")
        print(f"   Final average score: {avg_score:.2f}, Time in platoon: {time_in_platoon:.1f}s")
        
        # Check for potential removal from platoon
        if avg_score < 75 and current_status.startswith("joined_"):
            print(f"⚠️ Vehicle {vehicle_id} is at risk of removal from platoon (score: {avg_score:.2f})")

    return avg_score

def create_random_vehicle_behavior():
    """
    Generate a random behavior for a vehicle based on weighted probabilities.
    
    Returns:
        str: A behavior type ('safe', 'aggressive', 'speeding', or 'frequent_lane_change')
    """
    return random.choices(
        ['safe', 'aggressive', 'speeding', 'frequent_lane_change'],
        weights=[50, 20, 20, 10], k=1
    )[0]

def evaluate_vehicle_behavior(vehicle_id):
    """
    Evaluate a vehicle's behavior and calculate its trust score.
    
    Args:
        vehicle_id (str): Unique identifier for the vehicle
        
    Returns:
        tuple: (node_data, wallet_path, signed_trust_hash)
    """
    wallet_path = generate_wallet(vehicle_id)
    with open(wallet_path, "r") as f:
        key_bytes = bytes(json.load(f))
        public_key = str(Keypair.from_bytes(key_bytes).pubkey())

    # Use time-dependent randomness to ensure different behaviors each time
    current_time = time.time()
    random.seed(f"{vehicle_id}:{current_time}")
    behavior = create_random_vehicle_behavior()[:32]
    
    # Store previous platoon status for comparison
    previous_status = "not_joined"
    if vehicle_id in vehicle_metadata:
        previous_status = vehicle_metadata[vehicle_id].get("platoon_status", "not_joined")
    
    # Calculate trust score
    trust_score = calculate_trust_score(vehicle_id, behavior)

    # Set malicious flag based on classification
    # The actual malicious_flag in the blockchain is set by the platoon contract
    # This is just for local simulation tracking
    malicious = classify_vehicle(vehicle_id) == "malicious"
    malicious_flags[vehicle_id] = malicious
    zkp_status = not malicious

    # Create signed hash of trust score
    trust_str = f"{vehicle_id}:{trust_score:.2f}"
    signed_trust_hash = hashlib.sha256(trust_str.encode()).digest()

    # Get vehicle position and state from SUMO
    pos = traci.vehicle.getPosition(vehicle_id)
    lat, lon = convert_sumo_to_gps(pos[0], pos[1])
    speed = traci.vehicle.getSpeed(vehicle_id)
    lane = traci.vehicle.getLaneIndex(vehicle_id)

    # Initialize metadata if not exists
    vehicle_metadata.setdefault(vehicle_id, {
        "platoon_status": "not_joined",
        "previous_status": previous_status,  # Store previous status
        "join_history": [],
        "access_flags": {
            "can_share_data": not malicious,
            "can_join_platoon": zkp_status and trust_score >= 70
        }
    })

    # Store latest trust score in metadata for reference in other endpoints
    vehicle_metadata[vehicle_id]["trust_score"] = trust_score
    vehicle_metadata[vehicle_id]["vehicle_type"] = classify_vehicle(vehicle_id)

    # Construct node data
    node = {
        "vehicle_id": vehicle_id,
        "public_key": public_key,
        "trust_score": trust_score,
        "signed_trust_hash": signed_trust_hash.hex(),
        "platoon_status": vehicle_metadata[vehicle_id]["platoon_status"],
        "malicious": malicious,
        "join_history": vehicle_metadata[vehicle_id]["join_history"],
        "access_flags": vehicle_metadata[vehicle_id]["access_flags"],
        "behavior": behavior,
        "zkp_status": zkp_status,
        "lat": lat,
        "lon": lon,
        "speed": speed,
        "lane": lane
    }

    return node, wallet_path, signed_trust_hash

async def get_transaction_logs(tx_signature):
    """
    Fetch and print logs for a specific transaction.
    
    Args:
        tx_signature (str): Transaction signature to fetch logs for
    """
    conn = AsyncClient(SOLANA_RPC_URL)
    try:
        tx_data = await conn.get_transaction(tx_signature)
        if tx_data.value and tx_data.value.meta and tx_data.value.meta.log_messages:
            print("\n🔎 TRANSACTION LOGS:")
            for log in tx_data.value.meta.log_messages:
                print(f"  {log}")
            print("-------------------------------------")
        else:
            print(f"❌ No logs found for transaction {tx_signature}")
    except Exception as e:
        print(f"❌ Error fetching transaction logs: {e}")
    finally:
        await conn.close()

# =============================================================================
# API ROUTES - CORE VEHICLE DATA
# =============================================================================

@app.route('/realtime-vehicle-data', methods=['GET'])
def get_realtime_vehicle_data():
    """
    Get realtime data for all vehicles in the simulation.
    
    Returns:
        JSON: Vehicle data, RSU information, and platoon assignments
    """
    try:
        try:
            traci.getConnection()
        except:
            traci.init(SUMO_PORT)

        data = {}
        for _ in range(4):  # Simulate 4 steps to get more diverse data
            traci.simulationStep()
            current_time = traci.simulation.getTime()

            for veh_id in traci.vehicle.getIDList():
                node, _, _ = evaluate_vehicle_behavior(veh_id)
                data[veh_id] = node

                # Track trust score for CSV
                vehicle_logs.setdefault(veh_id, []).append({
                    'time': current_time,
                    'trust_score': node['trust_score'],
                    'behavior': node['behavior']
                })


        return jsonify({
            "vehicles": data,
            "rsus": {
                rsu_id: {
                    "lat": rsu["lat"],
                    "lon": rsu["lon"],
                    "wallet": rsu["wallet"]
                }
                for rsu_id, rsu in rsus.items()
            },
            "platoons": platoon_assignments
        })
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/vehicle-info/<vehicle_id>", methods=["GET"])
def get_vehicle_info(vehicle_id):
    """
    Get detailed information about a specific vehicle.
    
    Args:
        vehicle_id (str): Unique identifier for the vehicle
        
    Returns:
        JSON: Vehicle information including blockchain data
    """
    try:
        wallet_path = f"{WALLET_DIR}/{vehicle_id}_keypair.json"
        if not os.path.exists(wallet_path):
            return jsonify({"error": "Wallet not found"}), 404

        with open(wallet_path, "r") as f:
            secret_key = json.load(f)
        kp = Keypair.from_bytes(bytes(secret_key))
        public_key = kp.pubkey()

        balance = 0.0
        try:
            resp = solana_client.get_balance(public_key)
            balance = resp.value / 1_000_000_000
        except Exception as b_err:
            print(f"⚠️ Could not fetch balance for {vehicle_id}: {b_err}")

        async def fetch_pda_data():
            try:
                try:
                    connection = AsyncClient(SOLANA_RPC_URL)
                    dummy_wallet = Wallet(Keypair())
                    provider = Provider(connection, dummy_wallet)
                except Exception as conn_err:
                    print(f"⚠️ Connection error: {conn_err}")
                    raise
                
                try:
                    vehicle_program = Program(vehicle_idl, VEHICLE_PROGRAM_ID, provider)
                    platoon_program = Program(platoon_idl, PLATOON_PROGRAM_ID, provider)
                except Exception as prog_err:
                    print(f"⚠️ Program loading error: {prog_err}")
                    raise

                try:
                    # Compute PDA
                    pda, _ = PublicKey.find_program_address(
                        [b"vehicle_node", bytes(vehicle_id, "utf-8")],
                        VEHICLE_PROGRAM_ID
                    )
                except Exception as pda_err:
                    print(f"⚠️ PDA computation error: {pda_err}")
                    raise
                
                try:
                    info = await connection.get_account_info(pda)
                    if info.value is None:
                        print("ℹ️ PDA account not found on chain.")
                        await connection.close()
                        return {
                            "vehicle_id": vehicle_id,
                            "public_key": str(public_key),
                            "balance": balance,
                            "pda_joined": False
                        }
                except Exception as info_err:
                    print(f"⚠️ Account info error: {info_err}")
                    raise

                try:
                    vehicle_data = await vehicle_program.account["VehicleNode"].fetch(pda)
                except Exception as fetch_err:
                    print(f"⚠️ Vehicle data fetch error: {fetch_err}")
                    raise

                trust_score = vehicle_data.trust_score
                eligible_rsus = []

                # Replace or expand this list if more RSUs exist
                for rsu_id in ["rsu_1", "rsu_2"]:
                    try:
                        platoon_pda, _ = PublicKey.find_program_address(
                            [b"platoon", bytes(rsu_id, "utf-8")],
                            PLATOON_PROGRAM_ID
                        )
                        platoon_data = await platoon_program.account["Platoon"].fetch(platoon_pda)
                        if trust_score >= platoon_data.trust_threshold and not vehicle_data.malicious_flag:
                            eligible_rsus.append({
                                "rsu_id": rsu_id,
                                "threshold": platoon_data.trust_threshold
                            })
                    except Exception as rsu_err:
                        print(f"⚠️ RSU {rsu_id} fetch error: {rsu_err}")

                try:
                    await connection.close()
                except Exception as close_err:
                    print(f"⚠️ Connection close error: {close_err}")

                return {
                    "vehicle_id": vehicle_id,
                    "public_key": str(public_key),
                    "balance": balance,
                    "pda_joined": True,
                    "trust_score": int(vehicle_data.trust_score),
                    "platoon_status": vehicle_data.platoon_status,
                    "malicious_flag": vehicle_data.malicious_flag,
                    "access_flags": {
                        "can_join_platoon": vehicle_data.access_flags.can_join_platoon,
                        "can_share_data": vehicle_data.access_flags.can_share_data,
                    },
                    "join_history": vehicle_data.join_history,
                    "eligible_rsus": eligible_rsus,
                    "can_request_join": len(eligible_rsus) > 0
                }

            except Exception as err:
                print(f"🔥 Unexpected error for {vehicle_id}: {err}")
                return {
                    "vehicle_id": vehicle_id,
                    "public_key": str(public_key),
                    "balance": balance,
                    "pda_joined": False,
                    "error": str(err)
                }

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            vehicle_info = loop.run_until_complete(fetch_pda_data())
        except Exception as loop_err:
            print(f"⚠️ Event loop error: {loop_err}")
            raise
            
        return jsonify(vehicle_info)

    except Exception as e:
        print(f"❌ Error in get_vehicle_info: {e}")
        return jsonify({"error": str(e)}), 500
    
@app.route("/vehicle-classification", methods=["GET"])
def get_vehicle_classification():
    """
    Get the classification of all vehicles (normal or malicious).
    For monitoring purposes only.
    
    Returns:
        JSON: Classification information for all vehicles
    """
    classifications = {}
    for vehicle_id in vehicle_metadata:
        classifications[vehicle_id] = classify_vehicle(vehicle_id)
    
    return jsonify({
        "vehicle_types": classifications,
        "total_normal": sum(1 for v in classifications.values() if v == "normal"),
        "total_malicious": sum(1 for v in classifications.values() if v == "malicious"),
    })

# =============================================================================
# API ROUTES - BLOCKCHAIN ACTIONS
# =============================================================================

@app.route('/airdrop/<vehicle_id>', methods=['POST'])
def request_airdrop(vehicle_id):
    """
    Request an airdrop of SOL tokens to a vehicle's wallet.
    
    Args:
        vehicle_id (str): Unique identifier for the vehicle
        
    Returns:
        JSON: Result of the airdrop request
    """
    wallet_path = f"{WALLET_DIR}/{vehicle_id}_keypair.json"
    try:
        if not os.path.exists(wallet_path):
            return jsonify({"error": f"Wallet for {vehicle_id} not found."}), 404

        with open(wallet_path, "r") as f:
            secret_key = json.load(f)

        account = Keypair.from_bytes(bytes(secret_key))
        pubkey = str(account.pubkey())

        print(f"🚀 Requesting airdrop for {vehicle_id} at address {pubkey}...")

        result = subprocess.run(
            ["solana", "airdrop", "1", pubkey, "--url", SOLANA_RPC_URL],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print(f"✅ Airdrop request for {vehicle_id} successful.")
            return jsonify({"result": result.stdout.strip()}), 200
        else:
            print(f"❌ Airdrop failed for {vehicle_id}: {result.stderr.strip()}")
            return jsonify({
                "error": "Airdrop failed",
                "details": result.stderr.strip()
            }), 500

    except Exception as e:
        print(f"❌ Exception during airdrop: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500
    


@app.route("/update-trust/<vehicle_id>", methods=["POST"])
def update_trust_score(vehicle_id):
    """
    Update a vehicle's trust score on the blockchain.
    
    Args:
        vehicle_id (str): Unique identifier for the vehicle
        
    Returns:
        JSON: Result of the trust score update
    """
    try:
        # Step 1: Evaluate vehicle behavior
        try:
            node, wallet_path, _ = evaluate_vehicle_behavior(vehicle_id)
            trust_score = int(round(node["trust_score"]))
            behavior = node["behavior"]
            print(f"📡 Live trust score to update: {trust_score}")

            # Generate the hash for ZKP verification
            trust_str = f"{vehicle_id}:{trust_score}"
            signed_hash = hashlib.sha256(trust_str.encode()).digest()
        except Exception as eval_err:
            print(f"❌ Evaluation failed: {eval_err}")
            raise

        # Step 2: Load vehicle keypair
        try:
            with open(wallet_path, "r") as f:
                secret_key = json.load(f)
            kp = Keypair.from_bytes(bytes(secret_key))
        except Exception as key_err:
            print(f"🔐 Keypair loading failed: {key_err}")
            raise

        # Step 3: Async blockchain operations
        async def update_chain_data():
            connection = None
            try:
                connection = AsyncClient(SOLANA_RPC_URL)
                wallet = Wallet(kp)
                provider = Provider(connection, wallet)

                # Find vehicle PDA
                vehicle_program = Program(vehicle_idl, VEHICLE_PROGRAM_ID, provider)
                vehicle_pda, _ = PublicKey.find_program_address(
                    [b"vehicle_node", bytes(vehicle_id, "utf-8")],
                    VEHICLE_PROGRAM_ID
                )
                
                # Get current vehicle data
                vehicle_data_before = None
                try:
                    vehicle_data_before = await vehicle_program.account["VehicleNode"].fetch(vehicle_pda)
                    old_trust_score = vehicle_data_before.trust_score
                    platoon_status = vehicle_data_before.platoon_status
                    print(f"🔍 Previous trust score: {old_trust_score}, New trust score: {trust_score}")
                    print(f"🔍 Current platoon status: {platoon_status}")
                    print(f"🔍 Current malicious flag: {vehicle_data_before.malicious_flag}")
                except Exception as fetch_err:
                    print(f"⚠️ Could not fetch previous vehicle data: {fetch_err}")
                    old_trust_score = None
                    platoon_status = None
                
                # Check if vehicle is already flagged as malicious
                # If so, we should still update trust score but won't change the flag
                is_already_malicious = False
                if vehicle_data_before and hasattr(vehicle_data_before, "malicious_flag"):
                    is_already_malicious = vehicle_data_before.malicious_flag
                
                # Pre-check for large trust score drop (>5 points)
                suspicious_drop = False
                if old_trust_score is not None:
                    if old_trust_score > trust_score and (old_trust_score - trust_score) > 5:
                        # IMPORTANT: Only consider it suspicious if the vehicle is in a platoon
                        # This prevents false flags for normal trust score fluctuations
                        if platoon_status and platoon_status.startswith("joined_"):
                            print(f"⚠️ SUSPICIOUS: Large trust score drop detected ({old_trust_score} → {trust_score})")
                            suspicious_drop = True
                
                # 1. Update the vehicle's trust score and behavior
                print(f"✍️ Updating vehicle {vehicle_id} trust score to {trust_score}, behavior: {behavior}")
                vehicle_ctx = Context(
                    accounts={
                        "vehicle": vehicle_pda,
                        "authority": kp.pubkey(),
                    },
                    signers=[kp],
                )
                
                await vehicle_program.rpc["update_vehicle"](
                    trust_score,
                    behavior,
                    list(signed_hash),
                    ctx=vehicle_ctx
                )
                print("✅ Trust score updated in vehicle PDA")
                
                # 2. Only perform ZKP verification if not already malicious
                verified = True
                if not is_already_malicious:
                    if suspicious_drop:
                        print("🚨 Suspicious drop detected - confirming with backend classification")
                        # IMPORTANT: Only flag as malicious if our classification system also thinks it's malicious
                        # This will prevent normal vehicles from being falsely flagged
                        vehicle_type = classify_vehicle(vehicle_id)
                        if vehicle_type == "malicious":
                            print(f"⚠️ Vehicle {vehicle_id} is classified as malicious - flagging")
                            # Use invalid hash to mark vehicle as malicious
                            dummy_hash = bytes([0] * 32)
                            try:
                                await vehicle_program.rpc["verify_zkp"](
                                    trust_score,
                                    list(dummy_hash),  # Invalid hash will trigger malicious flag
                                    ctx=vehicle_ctx
                                )
                                print("✅ Successfully marked vehicle as malicious")
                                verified = False
                            except Exception as zkp_err:
                                print(f"⚠️ Error marking vehicle as malicious: {zkp_err}")
                        else:
                            print(f"ℹ️ Vehicle {vehicle_id} classified as normal despite score drop - not flagging")
                            # Use valid hash to avoid setting malicious flag
                            try:
                                await vehicle_program.rpc["verify_zkp"](
                                    trust_score,
                                    list(signed_hash),
                                    ctx=vehicle_ctx
                                )
                                print("✅ ZKP verification successful")
                            except Exception as zkp_err:
                                print(f"⚠️ ZKP verification error: {zkp_err}")
                    else:
                        # Regular ZKP verification
                        print(f"🔒 Running regular ZKP verification")
                        try:
                            await vehicle_program.rpc["verify_zkp"](
                                trust_score,
                                list(signed_hash),
                                ctx=vehicle_ctx
                            )
                            print("✅ ZKP verification successful")
                        except Exception as zkp_err:
                            print(f"⚠️ ZKP verification error: {zkp_err}")
                            verified = False
                
                # 3. If vehicle is in a platoon, update platoon data
                platoon_updated = False
                platoon_rsu_id = None
                
                if platoon_status and platoon_status.startswith("joined_"):
                    rsu_id = platoon_status.replace("joined_", "")
                    platoon_rsu_id = rsu_id
                    print(f"🔄 Vehicle is in platoon for RSU: {rsu_id}")
                    
                    # Find platoon PDA
                    platoon_pda, _ = PublicKey.find_program_address(
                        [b"platoon", bytes(rsu_id, "utf-8")],
                        PLATOON_PROGRAM_ID
                    )
                    
                    # Initialize platoon program
                    platoon_program = Program(platoon_idl, PLATOON_PROGRAM_ID, provider)
                    
                    # Now call request_join to update the trust score in the platoon
                    # The contract will handle any malicious detection or threshold violations
                    try:
                        print(f"📝 Invoking request_join to update trust score in platoon")
                        await platoon_program.rpc["request_join"](
                            vehicle_id,
                            trust_score,
                            bytes([]),  # Empty zkp_data
                            ctx=Context(
                                accounts={
                                    "platoon": platoon_pda,
                                    "vehicle": vehicle_pda,
                                    "vehicle_program": VEHICLE_PROGRAM_ID,
                                    "rsu_signer": kp.pubkey(),
                                },
                                signers=[kp]
                            )
                        )
                        print(f"✅ Successfully processed trust score update in platoon")
                        platoon_updated = True
                    except Exception as platoon_err:
                        error_str = str(platoon_err)
                        
                        # Parse the error message to understand what happened
                        print(f"ℹ️ Platoon update result: {error_str}")
                        
                        # Look for specific error messages
                        if "MaliciousVehicle" in error_str or "malicious" in error_str.lower():
                            print(f"🚨 Vehicle rejected from platoon as malicious")
                        elif "TrustTooLow" in error_str or "below threshold" in error_str.lower():
                            print(f"⚠️ Trust score below threshold - vehicle removed from platoon")
                        elif "InvalidStatus" in error_str:
                            print(f"⚠️ Invalid status error - attempting to fix vehicle status")
                            
                            # If we get an InvalidStatus error, it's likely the contract tried to
                            # use an invalid status value. Let's manually set a valid status.
                            try:
                                # Update to proper removal status first
                                await vehicle_program.rpc["join_platoon_and_share_data"](
                                    f"removed_from_{rsu_id}",
                                    ctx=Context(
                                        accounts={
                                            "vehicle": vehicle_pda,
                                            "rsu_signer": kp.pubkey(),
                                        },
                                        signers=[kp]
                                    )
                                )
                                print(f"✅ Updated status to removed_from_{rsu_id}")
                                
                                # Then set to not_joined
                                await vehicle_program.rpc["join_platoon_and_share_data"](
                                    "not_joined",
                                    ctx=Context(
                                        accounts={
                                            "vehicle": vehicle_pda,
                                            "rsu_signer": kp.pubkey(),
                                        },
                                        signers=[kp]
                                    )
                                )
                                print(f"✅ Updated status to not_joined")
                            except Exception as status_err:
                                print(f"⚠️ Error fixing vehicle status: {status_err}")
                
                # 4. Check final vehicle state
                final_vehicle_data = await vehicle_program.account["VehicleNode"].fetch(vehicle_pda)
                final_trust_score = final_vehicle_data.trust_score
                final_platoon_status = final_vehicle_data.platoon_status
                final_malicious_flag = final_vehicle_data.malicious_flag
                final_can_join = final_vehicle_data.access_flags.can_join_platoon
                
                # Return the final state information
                return {
                    "success": True,
                    "trust_score": final_trust_score,
                    "platoon_status": final_platoon_status,
                    "malicious_flag": final_malicious_flag,
                    "can_join_platoon": final_can_join,
                    "original_rsu_id": platoon_rsu_id,
                    "platoon_updated": platoon_updated,
                    "suspicious_drop": suspicious_drop,
                    "zkp_verified": verified
                }
            except Exception as rpc_err:
                print(f"❌ Blockchain update failed: {rpc_err}")
                return {"success": False, "error": str(rpc_err)}
            finally:
                # Make sure we always close the connection
                if connection:
                    await connection.close()

        # Step 4: Run event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(update_chain_data())
        
        if result["success"]:
            # Return the blockchain result directly
            response = {
                "status": "updated",
                "zkp_verified": result["zkp_verified"],
                "score": result["trust_score"],
                "platoon_status": result["platoon_status"],
                "malicious_flag": result["malicious_flag"],
                "can_join_platoon": result["can_join_platoon"]
            }
            
            # Add suspicious drop info if detected
            if result["suspicious_drop"]:
                response["suspicious_drop_detected"] = True
            
            # Add platoon info if applicable
            if result["original_rsu_id"] and result["platoon_updated"]:
                response["platoon_updated"] = True
                response["rsu_id"] = result["original_rsu_id"]
            
            return jsonify(response)
        else:
            return jsonify({"error": result["error"]}), 500

    except Exception as e:
        print(f"❌ Trust update error: {e}")
        return jsonify({"error": str(e)}), 500


async def register_vehicle_on_chain(vehicle_id: str, signed_trust_hash: bytes):
    """
    Register a vehicle's data on the blockchain.
    
    Args:
        vehicle_id (str): Unique identifier for the vehicle
        signed_trust_hash (bytes): Hash of the trust score data, signed by the vehicle
        
    Returns:
        tuple: (success, error_message)
    """
    try:
        print(f"🔄 Step 1: Loading wallet for {vehicle_id}")
        wallet_path = f"backend/vehicle_wallets/{vehicle_id}_keypair.json"
        with open(wallet_path, "r") as f:
            secret_key = json.load(f)
        kp = Keypair.from_bytes(bytes(secret_key))
        wallet = Wallet(kp)
    except Exception as e:
        print(f"❌ Step 1 (Wallet Load) failed for {vehicle_id}: {e}")
        return False, str(e)

    try:
        print("✅ Step 2: Creating connection and provider...")
        connection = AsyncClient(SOLANA_RPC_URL)
        provider = Provider(connection, wallet)
    except Exception as e:
        print(f"❌ Step 2 (Provider Init) failed for {vehicle_id}: {e}")
        return False, str(e)

    try:
        print("✅ Step 3: Loading Anchor program...")
        program = Program(vehicle_idl, VEHICLE_PROGRAM_ID, provider)
        print(f"✅ Program loaded: {type(program)}")
    except Exception as e:
        print(f"❌ Step 3 (Program Init) failed for {vehicle_id}: {e}")
        return False, str(e)

    try:
        print("✅ Step 4: Generating PDA...")
        pda, _ = PublicKey.find_program_address(
            [b"vehicle_node", bytes(vehicle_id, "utf-8")],
            VEHICLE_PROGRAM_ID
        )
        print(f"✅ PDA: {pda}")
    except Exception as e:
        print(f"❌ Step 4 (PDA Derivation) failed for {vehicle_id}: {e}")
        return False, str(e)

    try:
        print("✅ Step 5: Sending initialize_vehicle transaction...")
        print("📦 Accounts passed:", {
            "vehicle": pda,
            "authority": kp.pubkey(),
            "system_program": SYSTEM_PROGRAM_ID,
        })
        print("🔍 Available accounts:", list(program.account.keys()))
        ctx = Context(
            accounts={
                "vehicle": pda,
                "authority": kp.pubkey(),
                "system_program": SYSTEM_PROGRAM_ID,
            },
            signers=[kp],
        )
        await program.rpc["initialize_vehicle"](vehicle_id, ctx=ctx)
        print(f"🎉 Success: {vehicle_id} registered on-chain!")
        return True, "Success"

    except Exception as e:
        print(f"❌ Blockchain Error for {vehicle_id}: {e}")
        return False, str(e)

@app.route('/join-pda/<vehicle_id>', methods=['POST'])
def join_pda(vehicle_id):
    """
    Register a vehicle on the blockchain by creating a PDA (Program Derived Address).
    
    Args:
        vehicle_id (str): Unique identifier for the vehicle
        
    Returns:
        JSON: Result of the registration process
    """
    try:
        # Step 1: Evaluate vehicle behavior and generate trust data
        node, wallet_path, signed_trust_hash = evaluate_vehicle_behavior(vehicle_id)
        trust_score = int(round(node["trust_score"]))
        behavior = node["behavior"]

        # Step 2: Load vehicle wallet
        with open(wallet_path, "r") as f:
            secret_key = json.load(f)
        kp = Keypair.from_bytes(bytes(secret_key))
        public_key = kp.pubkey()

        # Step 3: Register or reinitialize vehicle on-chain
        async def register_vehicle_on_chain():
            try:
                print(f"🔄 Processing {vehicle_id} on-chain...")
                connection = AsyncClient(SOLANA_RPC_URL)
                wallet = Wallet(kp)
                provider = Provider(connection, wallet)
                program = Program(vehicle_idl, VEHICLE_PROGRAM_ID, provider)

                # Derive PDA
                pda, _ = PublicKey.find_program_address(
                    [b"vehicle_node", bytes(vehicle_id, "utf-8")],
                    VEHICLE_PROGRAM_ID
                )

                # Check if PDA exists
                account_info = await connection.get_account_info(pda)
                if account_info.value is not None:
                    print(f"ℹ️ Vehicle {vehicle_id} already initialized. Attempting update...")
                    try:
                        ctx = Context(accounts={"vehicle": pda}, signers=[kp])
                        await program.rpc["update_vehicle"](
                            trust_score,
                            behavior,
                            list(signed_trust_hash),
                            ctx=ctx
                        )
                        print(f"✅ Updated {vehicle_id} successfully.")
                        await connection.close()
                        return True, "Updated", str(pda)
                    except Exception as update_err:
                        print(f"⚠️ Update failed: {update_err}. Reinitializing {vehicle_id}...")
                        # If update fails, reinitialize (requires closing the old account first, but we'll assume overwrite for simplicity)
                        pass  # Fall through to initialization

                # Initialize or reinitialize
                ctx = Context(
                    accounts={
                        "vehicle": pda,
                        "authority": public_key,
                        "system_program": SYSTEM_PROGRAM_ID,
                    },
                    signers=[kp],
                )
                await program.rpc["initialize_vehicle"](vehicle_id, ctx=ctx)
                print(f"✅ Initialized {vehicle_id} successfully.")
                await connection.close()
                return True, "Initialized", str(pda)

            except Exception as e:
                print(f"❌ Blockchain error for {vehicle_id}: {e}")
                return False, str(e), None

        # Step 4: Execute the async registration
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        success, message, pda_address = loop.run_until_complete(register_vehicle_on_chain())

        # Step 5: Log ZKP data
        if vehicle_id not in zkp_logs:
            zkp_logs[vehicle_id] = []

        zkp_logs[vehicle_id].append({
            "hash": signed_trust_hash.hex(),
            "score": trust_score,
            "behavior": behavior,
            "result": "valid" if success else "invalid",
            "ts": datetime.now(timezone.utc).isoformat()
        })

        # Step 6: Check for tampering
        for entry in zkp_logs[vehicle_id][:-1]:
            if entry["hash"] == signed_trust_hash.hex():
                if entry["score"] != trust_score or entry["behavior"] != behavior:
                    print(f"🚨 ZKP tampering detected for {vehicle_id}!")
                    break

        # Step 7: Handle malicious status
        if malicious_flags.get(vehicle_id, False):
            print(f"❌ Vehicle {vehicle_id} marked as malicious!")
            return jsonify({
                "status": "failed",
                "reason": "Vehicle flagged as malicious",
                "pda": pda_address or str(public_key)
            }), 403

        # Step 8: Return response
        if success:
            return jsonify({
                "status": "joined",
                "pda": pda_address,
                "message": message
            })
        else:
            return jsonify({
                "status": "failed",
                "reason": message,
                "pda": str(public_key)
            }), 400

    except Exception as e:
        print(f"❌ General error for {vehicle_id}: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/verify-zkp/<vehicle_id>", methods=["POST"])
def verify_zkp(vehicle_id):
    """
    Verify a vehicle's ZKP (Zero-Knowledge Proof) on the blockchain.
    
    Args:
        vehicle_id (str): Unique identifier for the vehicle
        
    Returns:
        JSON: Result of the verification process
    """
    # Load trust score and hash from local memory
    node, wallet_path, signed_hash = evaluate_vehicle_behavior(vehicle_id)
    trust_score = int(round(node["trust_score"]))

    with open(wallet_path, "r") as f:
        secret = json.load(f)
    kp = Keypair.from_bytes(bytes(secret))

    async def run_zkp():
        conn = AsyncClient(SOLANA_RPC_URL)
        provider = Provider(conn, Wallet(kp))
        program = Program(vehicle_idl, VEHICLE_PROGRAM_ID, provider)
        pda, _ = PublicKey.find_program_address(
            [b"vehicle_node", bytes(vehicle_id, "utf-8")],
            VEHICLE_PROGRAM_ID
        )

        # Fixed context with authority account added
        ctx = Context(
            accounts={
                "vehicle": pda,
                "authority": kp.pubkey(),  # Added authority account
            },
            signers=[kp],
        )

        try:
            result = await program.rpc["verify_zkp"](
                trust_score,
                list(signed_hash),
                ctx=ctx
            )
            # Handle the case where result is a Signature object
            # Convert to boolean - if we get here, verification succeeded
            verified = True
        except Exception as e:
            print(f"ZKP verification failed: {e}")
            verified = False
        finally:
            await conn.close()
            
        return verified

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    passed = loop.run_until_complete(run_zkp())
    return jsonify({"zkp_verified": passed})

@app.route("/reset-vehicle/<vehicle_id>", methods=["POST"])
def reset_vehicle(vehicle_id):
    """
    Reset a vehicle's state on the blockchain.
    
    Args:
        vehicle_id (str): Unique identifier for the vehicle
        
    Returns:
        JSON: Result of the reset operation
    """
    try:
        wallet_path = f"{WALLET_DIR}/{vehicle_id}_keypair.json"
        with open(wallet_path, "r") as f:
            secret = json.load(f)
        kp = Keypair.from_bytes(bytes(secret))

        async def _reset():
            conn = AsyncClient(SOLANA_RPC_URL)
            wallet = Wallet(kp)
            provider = Provider(conn, wallet)
            program = Program(vehicle_idl, VEHICLE_PROGRAM_ID, provider)

            vehicle_pda, _ = PublicKey.find_program_address(
                [b"vehicle_node", bytes(vehicle_id, "utf-8")],
                VEHICLE_PROGRAM_ID
            )

            print(f"♻️ Resetting vehicle: {vehicle_id}")
            await program.rpc["reset_vehicle"](
                ctx=Context(
                    accounts={
                        "vehicle": vehicle_pda,
                        "authority": kp.pubkey(),
                        "system_program": SYSTEM_PROGRAM_ID,
                    },
                    signers=[kp]
                )
            )
            await conn.close()
            return True

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        success = loop.run_until_complete(_reset())
        return {"status": "reset_success"} if success else {"status": "reset_failed"}

    except Exception as e:
        return {"error": str(e)}, 500

@app.route("/reset-all-vehicles", methods=["POST"])
def reset_all_vehicles():
    """
    Reset all vehicles' states on the blockchain.
    
    Returns:
        JSON: Results of the reset operations for all vehicles
    """
    try:
        reset_results = {}

        # Look into wallet directory for all keypair files
        for filename in os.listdir(WALLET_DIR):
            if filename.endswith("_keypair.json"):
                vehicle_id = filename.replace("_keypair.json", "")
                wallet_path = os.path.join(WALLET_DIR, filename)

                try:
                    with open(wallet_path, "r") as f:
                        secret = json.load(f)
                    kp = Keypair.from_bytes(bytes(secret))

                    async def _reset():
                        conn = AsyncClient(SOLANA_RPC_URL)
                        provider = Provider(conn, Wallet(kp))
                        program = Program(vehicle_idl, VEHICLE_PROGRAM_ID, provider)

                        vehicle_pda, _ = PublicKey.find_program_address(
                            [b"vehicle_node", bytes(vehicle_id, "utf-8")],
                            VEHICLE_PROGRAM_ID
                        )

                        print(f"♻️ Resetting vehicle: {vehicle_id}")
                        await program.rpc["reset_vehicle"](
                            ctx=Context(
                                accounts={
                                    "vehicle": vehicle_pda,
                                    "authority": kp.pubkey(),
                                    "system_program": SYSTEM_PROGRAM_ID,
                                },
                                signers=[kp]
                            )
                        )
                        await conn.close()
                        return True

                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        success = loop.run_until_complete(_reset())
                        reset_results[vehicle_id] = "✅ Success" if success else "❌ Failed"
                    except Exception as reset_error:
                        reset_results[vehicle_id] = f"❌ Error: {str(reset_error)}"

                except Exception as wallet_error:
                    reset_results[vehicle_id] = f"❌ Wallet load error: {str(wallet_error)}"

        return jsonify(reset_results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# API ROUTES - PLATOON MANAGEMENT
# =============================================================================

@app.route("/close-platoon/<rsu_id>", methods=["POST"])
def close_platoon(rsu_id):
    """
    Close (disband) a platoon managed by an RSU.
    
    Args:
        rsu_id (str): Unique identifier for the RSU
        
    Returns:
        JSON: Result of the close operation
    """
    try:
        print(f"🧹 Closing platoon for RSU = {rsu_id}")

        # Load RSU wallet
        wallet_path = f"{RSU_WALLET_DIR}/{rsu_id}_keypair.json"
        if not os.path.exists(wallet_path):
            return {"error": f"RSU wallet for {rsu_id} not found."}, 404

        with open(wallet_path, "r") as f:
            secret = json.load(f)
        kp = Keypair.from_bytes(bytes(secret))
        wallet = Wallet(kp)

        # Derive PDA
        seed = bytes(rsu_id, "utf-8")
        platoon_pda, _ = PublicKey.find_program_address(
            [b"platoon", seed],
            PLATOON_PROGRAM_ID
        )

        print(f"📌 Platoon PDA: {platoon_pda}")

        # Async close logic
        async def close():
            conn = AsyncClient(SOLANA_RPC_URL)
            provider = Provider(conn, wallet)
            program = Program(platoon_idl, PLATOON_PROGRAM_ID, provider)

            try:
                tx_sig = await program.rpc["close_platoon"](
                    ctx=Context(
                        accounts={
                            "platoon": platoon_pda,
                            "creator": kp.pubkey(),
                        },
                        signers=[kp]
                    )
                )
                print(f"✅ Platoon closed: {tx_sig}")
                await conn.close()
                return {"status": "platoon_closed", "tx": tx_sig}

            except Exception as e:
                print(f"❌ Failed to close platoon: {e}")
                await conn.close()
                return {"error": str(e)}, 500

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(close())

    except Exception as e:
        print(f"🔥 Top-level error in close_platoon: {e}")
        return {"error": str(e)}, 500

@app.route("/platoon-request/<vehicle_id>/<rsu_id>", methods=["POST"])
def platoon_request(vehicle_id, rsu_id):
    """
    Send a request for a vehicle to join a platoon.
    
    Args:
        vehicle_id (str): Unique identifier for the vehicle
        rsu_id (str): Unique identifier for the RSU managing the platoon
        
    Returns:
        JSON: Result of the join request
    """
    try:
        print("🚀 START: Platoon request route triggered")
        print(f"📦 vehicle_id = '{vehicle_id}' | rsu_id = '{rsu_id}'")

        # Load vehicle wallet
        wallet_path = f"{WALLET_DIR}/{vehicle_id}_keypair.json"
        with open(wallet_path, "r") as f:
            secret = json.load(f)
        kp = Keypair.from_bytes(bytes(secret))
        wallet = Wallet(kp)

        # Derive PDAs
        vehicle_seed = bytes(vehicle_id, "utf-8")
        rsu_seed = bytes(rsu_id, "utf-8")

        vehicle_pda, _ = PublicKey.find_program_address(
            [b"vehicle_node", vehicle_seed],
            VEHICLE_PROGRAM_ID
        )
        platoon_pda, _ = PublicKey.find_program_address(
            [b"platoon", rsu_seed],
            PLATOON_PROGRAM_ID
        )

        print(f"🔑 Vehicle PDA: {vehicle_pda}")
        print(f"🔑 Platoon PDA: {platoon_pda}")

        # Async Join Logic
        async def join():
            conn = AsyncClient(SOLANA_RPC_URL)
            provider = Provider(conn, wallet)
            platoon_program = Program(platoon_idl, PLATOON_PROGRAM_ID, provider)
            vehicle_program = Program(vehicle_idl, VEHICLE_PROGRAM_ID, provider)

            # Fetch trust score and signed hash from vehicle PDA
            try:
                vehicle_data = await vehicle_program.account["VehicleNode"].fetch(vehicle_pda)
                trust_score = vehicle_data.trust_score
                signed_hash = vehicle_data.signed_trust_hash

                print(f"\n🔎 DETAILED VEHICLE STATE BEFORE JOIN:")
                vehicle_data = await vehicle_program.account["VehicleNode"].fetch(vehicle_pda)
                print(f"  Vehicle ID: {vehicle_data.vehicle_id}")
                print(f"  Trust Score: {vehicle_data.trust_score}")
                print(f"  Malicious Flag: {vehicle_data.malicious_flag}")  # This is the critical value
                print(f"  Access Flags: can_join_platoon={vehicle_data.access_flags.can_join_platoon}, can_share_data={vehicle_data.access_flags.can_share_data}")
                print(f"  Platoon Status: {vehicle_data.platoon_status}")
                print(f"  Owner: {vehicle_data.owner}")

                if isinstance(signed_hash, list):
                    signed_hash = bytes(signed_hash)

                tx_sig = await platoon_program.rpc["request_join"](
                    vehicle_id,
                    trust_score,
                    signed_hash,
                    ctx=Context(
                        accounts={
                            "platoon": platoon_pda,
                            "vehicle": vehicle_pda,
                            "vehicle_program": VEHICLE_PROGRAM_ID,
                            "rsu_signer": kp.pubkey(),
                        },
                        signers=[kp]
                    )
                )
                print(f"✅ Join request sent successfully: {tx_sig}")
                await conn.close()
                return True, str(platoon_pda)

            except Exception as err:
                print(f"❌ Join failed: {err}")
                await conn.close()
                return False, str(err)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        success, result = loop.run_until_complete(join())

        if success:
            return jsonify({
                "status": "joined",
                "vehicle": vehicle_id,
                "platoon": result
            })
        else:
            return jsonify({"error": result}), 500

    except Exception as e:
        print(f"🔥 Top-level error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/create-platoon-contract/<rsu_id>/<int:threshold>', methods=['POST'])
def create_platoon_contract(rsu_id, threshold):
    """
    Create or update a platoon contract on the blockchain.
    
    Args:
        rsu_id (str): Unique identifier for the RSU
        threshold (int): Minimum trust score required to join the platoon
        
    Returns:
        JSON: Result of the create/update operation
    """
    try:
        print(f"🚀 Creating/Updating platoon for RSU: {rsu_id}, Threshold: {threshold}")
        kp, wallet_path, _ = generate_rsu_wallet(rsu_id)
        wallet = Wallet(kp)
        print(f"🔑 Wallet loaded: {kp.pubkey()}")

        async def handle_platoon():
            try:
                connection = AsyncClient(SOLANA_RPC_URL)
                provider = Provider(connection, wallet)
                program = Program(platoon_idl, PLATOON_PROGRAM_ID, provider)

                # Derive PDA
                pda, bump = PublicKey.find_program_address(
                    [b"platoon", bytes(rsu_id, "utf-8")],
                    PLATOON_PROGRAM_ID
                )
                print(f"📍 Platoon PDA: {pda}, Bump: {bump}")

                # Check if PDA exists
                info = await connection.get_account_info(pda)
                status = None

                if info.value is not None:
                    print(f"🔁 PDA exists. Fetching current data...")
                    try:
                        platoon_data = await program.account["Platoon"].fetch(pda)
                        print(f"🏛️ Current RSU ID: {platoon_data.rsu_id}, Threshold: {platoon_data.trust_threshold}, Creator: {platoon_data.created_by}")
                        if platoon_data.created_by != kp.pubkey():
                            raise ValueError(f"Creator mismatch: Expected {kp.pubkey()}, Got {platoon_data.created_by}")
                    except Exception as fetch_err:
                        print(f"❌ Failed to fetch platoon data: {fetch_err}")
                        raise

                    print(f"🔄 Updating threshold to {threshold}")
                    ctx = Context(
                        accounts={"platoon": pda, "creator": kp.pubkey()},
                        signers=[kp],
                    )
                    try:
                        tx_sig = await program.rpc["update_threshold"](threshold, ctx=ctx)
                        print(f"✅ Threshold updated. Tx: {tx_sig}")
                        status = "updated"
                    except Exception as update_err:
                        print(f"❌ Update threshold failed: {update_err}")
                        raise
                else:
                    print(f"✨ Initializing new platoon with threshold {threshold}")
                    ctx = Context(
                        accounts={
                            "platoon": pda,
                            "creator": kp.pubkey(),
                            "system_program": SYSTEM_PROGRAM_ID,
                        },
                        signers=[kp],
                    )
                    try:
                        tx_sig = await program.rpc["initialize_platoon"](rsu_id, threshold, ctx=ctx)
                        print(f"✅ Platoon initialized. Tx: {tx_sig}")
                        status = "created"
                    except Exception as init_err:
                        print(f"❌ Initialize platoon failed: {init_err}")
                        raise

                balance = (await connection.get_balance(kp.pubkey())).value / 1_000_000_000
                await connection.close()
                return status, str(pda), balance

            except Exception as e:
                print(f"❌ Error during platoon handling: {e}")
                return None, None, None

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        status, pda_str, balance = loop.run_until_complete(handle_platoon())

        if not pda_str:
            return jsonify({"error": "Failed to create or update platoon"}), 500

        return jsonify({
            "status": status,
            "rsu_id": rsu_id,
            "threshold": threshold,
            "wallet_address": str(kp.pubkey()),
            "platoon_pda": pda_str,
            "balance": round(balance, 4)
        })

    except Exception as e:
        print(f"❌ Error in create_platoon_contract: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/rsu-airdrop/<rsu_id>', methods=['POST'])
def rsu_airdrop(rsu_id):
    """
    Request an airdrop of SOL tokens to an RSU's wallet.
    
    Args:
        rsu_id (str): Unique identifier for the RSU
        
    Returns:
        JSON: Result of the airdrop request
    """
    try:
        wallet_path = f"{RSU_WALLET_DIR}/{rsu_id}_keypair.json"
        if not os.path.exists(wallet_path):
            return jsonify({"error": "Wallet for RSU not found."}), 404

        with open(wallet_path, "r") as f:
            secret = json.load(f)

        kp = Keypair.from_bytes(bytes(secret))
        pubkey = str(kp.pubkey())

        result = subprocess.run(
            ["solana", "airdrop", "1", pubkey, "--url", SOLANA_RPC_URL],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            return jsonify({"message": f"Airdrop successful for RSU {rsu_id}"}), 200
        else:
            return jsonify({"error": result.stderr.strip()}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/platoon-info/<rsu_id>", methods=["GET"])
def get_platoon_info(rsu_id):
    """
    Get detailed information about a platoon managed by an RSU.
    
    Args:
        rsu_id (str): Unique identifier for the RSU
        
    Returns:
        JSON: Detailed platoon information
    """
    rsu_id = rsu_id.lower()
    try:
        print(f"📡 Fetching platoon info for RSU: {rsu_id}")
        kp, _, _ = generate_rsu_wallet(rsu_id)
        pubkey = kp.pubkey()
        print(f"🔑 Wallet: {pubkey}")
        pda, _ = PublicKey.find_program_address(
            [b"platoon", bytes(rsu_id, "utf-8")],
            PLATOON_PROGRAM_ID
        )
        print(f"📍 Platoon PDA: {pda}")

        async def fetch_platoon_data():
            try:
                conn = AsyncClient(SOLANA_RPC_URL)
                provider = Provider(conn, Wallet(kp))
                program = Program(platoon_idl, PLATOON_PROGRAM_ID, provider)
                vehicle_program = Program(vehicle_idl, VEHICLE_PROGRAM_ID, provider)
                
                info = await conn.get_account_info(pda)
                if info.value is None:
                    print(f"❌ Platoon not initialized")
                    return None
                
                platoon_data = await program.account["Platoon"].fetch(pda)
                print(f"🏛️ Raw platoon data: {platoon_data.__dict__}")
                print(f"🏛️ RSU ID: {platoon_data.rsu_id}, Threshold: {platoon_data.trust_threshold}, Members: {platoon_data.members}")
                
                members = []
                try:
                    for member in platoon_data.members:
                        # Access MemberInfo struct fields directly
                        members.append({
                            "vehicle_id": member.vehicle_id,
                            "trust_score": member.trust_score
                        })
                except Exception as unpack_err:
                    print(f"⚠️ Failed to process members: {unpack_err}")
                    print(f"⚠️ Returning empty members list as fallback")
                    members = []
                
                # Track malicious vehicles
                malicious_members = []
                suspicious_activities = []
                
                # Process flagged vehicles if available in the platoon data
                if hasattr(platoon_data, "flagged_vehicles"):
                    for vehicle_id in platoon_data.flagged_vehicles:
                        malicious_members.append({
                            "vehicle_id": vehicle_id,
                            "flag_reason": "on_chain_flag",
                            "actual_type": classify_vehicle(vehicle_id) if "classify_vehicle" in globals() else "unknown"
                        })
                
                # Process suspicious activities if available
                if hasattr(platoon_data, "suspicious_activities"):
                    for activity in platoon_data.suspicious_activities:
                        suspicious_activities.append({
                            "vehicle_id": activity.vehicle_id,
                            "activity_type": activity.activity_type,
                            "timestamp": activity.timestamp,
                            "score": activity.score
                        })
                
                # Also check for malicious flags in vehicle accounts
                for member in members:
                    vehicle_id = member["vehicle_id"]
                    try:
                        veh_pda, _ = PublicKey.find_program_address(
                            [b"vehicle_node", bytes(vehicle_id, "utf-8")],
                            VEHICLE_PROGRAM_ID
                        )
                        vehicle_data = await vehicle_program.account["VehicleNode"].fetch(veh_pda)
                        
                        # Check if vehicle has malicious flag but isn't already in our list
                        if (hasattr(vehicle_data, "malicious_flag") and 
                            vehicle_data.malicious_flag and 
                            not any(m["vehicle_id"] == vehicle_id for m in malicious_members)):
                            
                            malicious_members.append({
                                "vehicle_id": vehicle_id,
                                "trust_score": member["trust_score"],
                                "flag_reason": "vehicle_account_flag",
                                "actual_type": classify_vehicle(vehicle_id) if "classify_vehicle" in globals() else "unknown"
                            })
                    except Exception as veh_err:
                        print(f"⚠️ Error fetching vehicle data: {veh_err}")
                
                balance = (await conn.get_balance(pubkey)).value / 1_000_000_000
                await conn.close()
                
                return {
                    "rsu_id": platoon_data.rsu_id,
                    "threshold": platoon_data.trust_threshold,
                    "members": members,
                    "wallet": str(pubkey),
                    "platoon_pda": str(pda),
                    "balance": round(balance, 4),
                    "created_by": str(platoon_data.created_by),
                    "malicious_members": malicious_members,
                    "suspicious_activities": suspicious_activities
                }
            except Exception as e:
                print(f"⚠️ Failed to fetch Platoon data for {rsu_id}: {e}")
                return None

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        data = loop.run_until_complete(fetch_platoon_data())
        
        if data is None:
            response = {
                "wallet": str(pubkey),
                "balance": 0.0,
                "platoon_pda": str(pda),
                "error": f"Platoon PDA not initialized for {rsu_id}"
            }
            return jsonify(response), 200
            
        return jsonify(data), 200
        
    except Exception as e:
        print(f"❌ Error in get_platoon_info: {e}")
        return jsonify({"error": str(e)}), 500
    
@app.route("/platoon-members/<rsu_id>", methods=["GET"])
def get_platoon_members(rsu_id):
    """
    Get the list of members in a platoon managed by an RSU.
    
    Args:
        rsu_id (str): Unique identifier for the RSU
        
    Returns:
        JSON: List of platoon members with their trust scores
    """
    try:
        rsu_id = rsu_id.lower()
        pda, _ = PublicKey.find_program_address(
            [b"platoon", bytes(rsu_id, "utf-8")],
            PLATOON_PROGRAM_ID
        )

        async def fetch_members():
            conn = AsyncClient(SOLANA_RPC_URL)
            provider = Provider(conn, Wallet(Keypair()))  # dummy wallet
            program = Program(platoon_idl, PLATOON_PROGRAM_ID, provider)
            vehicle_program = Program(vehicle_idl, VEHICLE_PROGRAM_ID, provider)

            members_list = []

            try:
                platoon = await program.account["Platoon"].fetch(pda)
                for pubkey in platoon.members:
                    try:
                        vehicle_data = await vehicle_program.account["VehicleNode"].fetch(pubkey)
                        members_list.append({
                            "vehicle_id": vehicle_data.vehicle_id,
                            "trust_score": int(vehicle_data.trust_score)
                        })
                    except Exception as inner_err:
                        members_list.append({
                            "vehicle_id": str(pubkey),
                            "trust_score": "N/A"
                        })

            except Exception as e:
                print(f"❌ Failed to fetch platoon members: {e}")
                await conn.close()
                return []

            await conn.close()
            return members_list

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        members = loop.run_until_complete(fetch_members())
        return jsonify({"members": members}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/remove-from-platoon/<vehicle_id>/<rsu_id>", methods=["POST"])
def remove_vehicle_from_platoon(vehicle_id, rsu_id):
    """
    Remove a vehicle from a platoon.
    
    Args:
        vehicle_id (str): Unique identifier for the vehicle
        rsu_id (str): Unique identifier for the RSU managing the platoon
        
    Returns:
        JSON: Result of the removal operation
    """
    try:
        print(f"🚨 Remove request: Vehicle ID = {vehicle_id}, RSU = {rsu_id}")
        
        # Load RSU wallet
        wallet_path = f"{RSU_WALLET_DIR}/{rsu_id}_keypair.json"
        if not os.path.exists(wallet_path):
            return {"error": f"RSU wallet for {rsu_id} not found."}, 404
            
        with open(wallet_path, "r") as f:
            secret = json.load(f)
        kp = Keypair.from_bytes(bytes(secret))
        
        # Derive platoon PDA
        rsu_seed = bytes(rsu_id, "utf-8")
        platoon_pda, _ = PublicKey.find_program_address(
            [b"platoon", rsu_seed],
            PLATOON_PROGRAM_ID
        )
        
        print(f"📌 Platoon PDA: {platoon_pda}")
        
        # Async removal logic
        async def remove():
            conn = AsyncClient(SOLANA_RPC_URL)
            provider = Provider(conn, Wallet(kp))
            platoon_program = Program(platoon_idl, PLATOON_PROGRAM_ID, provider)
            vehicle_program = Program(vehicle_idl, VEHICLE_PROGRAM_ID, provider)
            
            try:
                # Step 1: Check if platoon exists and if vehicle is in the platoon
                try:
                    platoon_data = await platoon_program.account["Platoon"].fetch(platoon_pda)
                    print(f"🔍 Platoon members: {[member.vehicle_id for member in platoon_data.members]}")
                    
                    found_vehicle = False
                    for member in platoon_data.members:
                        if member.vehicle_id == vehicle_id:
                            found_vehicle = True
                            break
                    
                    if not found_vehicle:
                        print(f"⚠️ Vehicle {vehicle_id} not found in platoon {rsu_id}")
                        await conn.close()
                        return {"error": f"Vehicle {vehicle_id} not found in platoon {rsu_id}"}, 404
                except Exception as platoon_err:
                    print(f"❌ Could not fetch platoon data: {platoon_err}")
                    await conn.close()
                    return {"error": f"Could not fetch platoon data: {str(platoon_err)}"}, 500
                
                # Step 2: Try multiple possible ways to derive the vehicle PDA
                candidate_pdas = []
                
                # Standard casing
                vehicle_pda, _ = PublicKey.find_program_address(
                    [b"vehicle_node", bytes(vehicle_id, "utf-8")],
                    VEHICLE_PROGRAM_ID
                )
                candidate_pdas.append(("Regular", vehicle_pda))
                
                # Lowercase
                vehicle_pda_lower, _ = PublicKey.find_program_address(
                    [b"vehicle_node", bytes(vehicle_id.lower(), "utf-8")],
                    VEHICLE_PROGRAM_ID
                )
                candidate_pdas.append(("Lowercase", vehicle_pda_lower))
                
                # Uppercase
                vehicle_pda_upper, _ = PublicKey.find_program_address(
                    [b"vehicle_node", bytes(vehicle_id.upper(), "utf-8")],
                    VEHICLE_PROGRAM_ID
                )
                candidate_pdas.append(("Uppercase", vehicle_pda_upper))
                
                # Check each candidate PDA to see if it exists on-chain
                print(f"🧪 Testing {len(candidate_pdas)} candidate vehicle PDAs")
                valid_pdas = []
                
                for label, pda in candidate_pdas:
                    info = await conn.get_account_info(pda)
                    exists = info.value is not None
                    print(f"  - {label}: {pda} {'✅ EXISTS' if exists else '❌ DOES NOT EXIST'}")
                    if exists:
                        try:
                            # Try to fetch the account data to confirm it's a vehicle account
                            vehicle_data = await vehicle_program.account["VehicleNode"].fetch(pda)
                            print(f"    ℹ️ Vehicle ID from account: {vehicle_data.vehicle_id}")
                            valid_pdas.append((label, pda, vehicle_data.vehicle_id))
                        except Exception as fetch_err:
                            print(f"    ⚠️ Account exists but could not fetch data: {fetch_err}")
                
                if not valid_pdas:
                    print(f"❌ No valid vehicle PDAs found for {vehicle_id}")
                    await conn.close()
                    return {"error": f"No valid vehicle PDAs found for {vehicle_id}"}, 404
                
                # Use the first valid PDA (or you could choose based on some priority)
                chosen_label, chosen_pda, actual_vehicle_id = valid_pdas[0]
                print(f"🎯 Chosen vehicle PDA: {chosen_label} - {chosen_pda} with ID {actual_vehicle_id}")
                
                # Execute the removal with the verified PDA
                tx = await platoon_program.rpc["remove_vehicle"](
                    actual_vehicle_id,  # Use the actual vehicle ID from the account
                    ctx=Context(
                        accounts={
                            "platoon": platoon_pda,
                            "vehicle": chosen_pda,
                            "vehicle_program": VEHICLE_PROGRAM_ID,
                            "rsu_signer": kp.pubkey(),
                        },
                        signers=[kp]
                    )
                )
                
                print(f"✅ Removed vehicle {actual_vehicle_id} from platoon {rsu_id}")
                await conn.close()
                return {"status": f"✅ Removed vehicle from {rsu_id}", "tx": str(tx)}
                
            except Exception as rpc_err:
                print(f"❌ Smart contract call failed: {rpc_err}")
                if hasattr(rpc_err, "logs") and rpc_err.logs:
                    print("Error logs:")
                    for log in rpc_err.logs:
                        print(f"  {log}")
                await conn.close()
                return {"error": str(rpc_err)}, 500
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return jsonify(loop.run_until_complete(remove()))
        
    except Exception as e:
        print(f"🔥 Top-level error in remove-from-platoon: {e}")
        return {"error": str(e)}, 500

@app.route("/remove-all-from-platoon/<rsu_id>", methods=["POST"])
def remove_all_from_platoon(rsu_id):
    """
    Remove all vehicles from a platoon.
    
    Args:
        rsu_id (str): Unique identifier for the RSU managing the platoon
        
    Returns:
        JSON: Results of the removal operations
    """
    try:
        print(f"🚨 Removing all members from platoon: RSU = {rsu_id}")

        wallet_path = f"{RSU_WALLET_DIR}/{rsu_id}_keypair.json"
        if not os.path.exists(wallet_path):
            return {"error": f"RSU wallet for {rsu_id} not found."}, 404

        with open(wallet_path, "r") as f:
            secret = json.load(f)
        kp = Keypair.from_bytes(bytes(secret))

        async def _remove_all():
            conn = AsyncClient(SOLANA_RPC_URL)
            provider = Provider(conn, Wallet(kp))
            program = Program(platoon_idl, PLATOON_PROGRAM_ID, provider)

            platoon_seed = bytes(rsu_id, "utf-8")
            platoon_pda, _ = PublicKey.find_program_address(
                [b"platoon", platoon_seed],
                PLATOON_PROGRAM_ID
            )

            try:
                platoon_data = await program.account["Platoon"].fetch(platoon_pda)
                members = platoon_data.members
                print(f"🔍 Found {len(members)} members in platoon")

                removed = []
                failed = []

                for member in members:
                    vehicle_id = member.vehicle_id

                    vehicle_pda, _ = PublicKey.find_program_address(
                        [b"vehicle_node", bytes(vehicle_id, "utf-8")],
                        VEHICLE_PROGRAM_ID
                    )

                    try:
                        await program.rpc["remove_vehicle"](
                            vehicle_id,
                            ctx=Context(
                                accounts={
                                    "platoon": platoon_pda,
                                    "vehicle": vehicle_pda,
                                    "vehicle_program": VEHICLE_PROGRAM_ID,
                                    "rsu_signer": kp.pubkey(),
                                },
                                signers=[kp]
                            )
                        )
                        print(f"✅ Removed {vehicle_id}")
                        removed.append(vehicle_id)
                    except Exception as err:
                        print(f"❌ Failed to remove {vehicle_id}: {err}")
                        failed.append(vehicle_id)

                await conn.close()
                return {
                    "status": "completed",
                    "removed": removed,
                    "failed": failed
                }
            except Exception as e:
                await conn.close()
                print(f"❌ Error during removal: {e}")
                return {"error": str(e)}, 500

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return jsonify(loop.run_until_complete(_remove_all()))

    except Exception as e:
        print(f"🔥 Top-level error in remove_all_from_platoon: {e}")
        return {"error": str(e)}, 500

if __name__ == '__main__':
    print("🚀 Starting Flask API on http://127.0.0.1:5002/")
    app.run(debug=True, port=5002)
