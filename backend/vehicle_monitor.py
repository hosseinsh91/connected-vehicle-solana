"""
Vehicle Monitor - Trust and Platoon Analysis System

This script monitors vehicles in a simulation environment, tracking trust scores, 
platoon memberships, and transaction metrics. It generates visualizations and 
analytics on system performance, malicious vehicle detection, and resource usage.
"""

import asyncio
import random
import time
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import requests
import json
import resource
import aiohttp
import os
from contextlib import asynccontextmanager
import seaborn as sns

# Increase file descriptor limits
try:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    print(f"Current file descriptor limits: soft={soft}, hard={hard}")
    
    # Increase to the hard limit or a reasonable number
    new_soft = min(hard, 4096)
    resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
    print(f"Increased file descriptor limit to: soft={new_soft}, hard={hard}")
except Exception as e:
    print(f"Could not adjust file descriptor limits: {e}")

# Connection pooling
session = None

@asynccontextmanager
async def get_session():
    """Get or create an aiohttp ClientSession with proper connection pooling."""
    global session
    if session is None:
        session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=20))
    try:
        yield session
    finally:
        pass  # Will close at end of program

# Configuration
UPDATE_INTERVAL = 20  # Update trust scores every 20 seconds
MONITORING_DURATION = 50  # 50 seconds for demo purposes
API_BASE_URL = "http://localhost:5002"
MAX_VEHICLES = 100  # Total vehicles to add during monitoring
VEHICLE_ADDITION_PATTERN = "linear"  # "linear" or "burst"
VEHICLE_PREFIX = "veh"  # Prefix for vehicle IDs

# Monitoring data structure
monitoring_data = {
    "trust_scores": [],
    "platoon_memberships": {},
    "events": [],
    "active_vehicles": set(),
    "sol_usage": {},
    "transaction_latency": {
        "trust_update": [],
        "zkp_verification": [],
        "platoon_join": [],
        "platoon_leave": [],
        "pda_join": []
    }
}

# Track vehicle addition times
vehicle_addition_times = {}
# Vehicle type tracking
vehicle_types = {}  # Will store vehicle_id -> "normal" or "malicious" from evaluation
trust_score_changes = {
    "normal": [],  # Tracks changes for normal vehicles
    "malicious": []  # Tracks changes for malicious vehicles
}
detection_stats = {
    "true_positives": 0,  # Malicious vehicles correctly detected
    "false_positives": 0,  # Normal vehicles incorrectly flagged
    "true_negatives": 0,  # Normal vehicles correctly not flagged
    "false_negatives": 0  # Malicious vehicles not detected
}

def print_live_stats():
    """Print live evaluation statistics"""
    trust_scores = monitoring_data["trust_scores"]
    events = monitoring_data["events"]
    
    # Calculate statistics
    if trust_scores:
        recent_scores = trust_scores[-min(10, len(trust_scores)):]
        avg_score = sum(s["trust_score"] for s in recent_scores) / len(recent_scores)
        
        join_attempts = [e for e in events if e["event_type"] == "platoon_join_attempt"]
        successful_joins = [e for e in join_attempts if e["success"]]
        
        # Calculate trust score distribution
        score_ranges = {"<60": 0, "60-70": 0, "70-80": 0, "80-90": 0, "90+": 0}
        for score in trust_scores:
            ts = score["trust_score"]
            if ts < 60:
                score_ranges["<60"] += 1
            elif ts < 70:
                score_ranges["60-70"] += 1
            elif ts < 80:
                score_ranges["70-80"] += 1
            elif ts < 90:
                score_ranges["80-90"] += 1
            else:
                score_ranges["90+"] += 1
                
        # Print statistics
        print("\n=== LIVE EVALUATION STATS ===")
        print(f"Active Vehicles: {len(monitoring_data['active_vehicles'])}")
        print(f"Total Trust Updates: {len(trust_scores)}")
        print(f"Average Trust Score: {avg_score:.2f}")
        print(f"Join Attempts: {len(join_attempts)}")
        print(f"Successful Joins: {len(successful_joins)}")
        print(f"Success Rate: {len(successful_joins)/len(join_attempts)*100:.1f}%" if join_attempts else "N/A")
        print(f"Trust Score Distribution: {score_ranges}")
        print("=============================\n")

async def check_for_active_vehicles():
    """Check the SUMO simulation for real vehicles with connection pooling"""
    try:
        async with get_session() as session:
            async with session.get(f"{API_BASE_URL}/realtime-vehicle-data") as response:
                if response.status == 200:
                    data = await response.json()
                    vehicles = data.get("vehicles", {})
                    
                    # Log what vehicles are actually in the system
                    if vehicles:
                        print(f"Found {len(vehicles)} vehicles in SUMO: {list(vehicles.keys())}")
                    else:
                        print("No vehicles currently in SUMO simulation")
                    
                    # Add any new vehicles to monitoring
                    for vehicle_id in vehicles:
                        if vehicle_id not in monitoring_data["active_vehicles"]:
                            await add_vehicle_to_monitoring(vehicle_id)
                    
                    return len(vehicles) > 0
                else:
                    print(f"Error getting vehicle data: {response.status}")
                    return False
    except Exception as e:
        print(f"Error checking for active vehicles: {e}")
        return False

async def add_vehicles_over_time(duration_seconds):
    """Monitor the SUMO simulation and add vehicles as they appear"""
    print(f"Starting vehicle monitoring over {duration_seconds} seconds...")
    
    start_time = time.time()
    elapsed = 0
    
    # Main loop to monitor for vehicles during the entire duration
    while elapsed < duration_seconds:
        # Check for real vehicles in SUMO
        found_vehicles = await check_for_active_vehicles()
        
        if not found_vehicles:
            print("Waiting for vehicles to appear in SUMO simulation...")
        
        # Short delay before checking again
        await asyncio.sleep(5)
        
        current_time = time.time()
        elapsed = current_time - start_time
    
    print(f"Completed monitoring after {elapsed:.1f} seconds")
    print(f"Total vehicles added: {len(monitoring_data['active_vehicles'])}")

async def add_vehicle_to_monitoring(vehicle_id):
    """Add a vehicle to monitoring with improved connection handling"""
    try:
        async with get_session() as session:
            # Check if vehicle exists in SUMO
            async with session.get(f"{API_BASE_URL}/realtime-vehicle-data") as response:
                if response.status == 200:
                    data = await response.json()
                    vehicles = data.get("vehicles", {})
                    
                    if vehicle_id not in vehicles:
                        print(f"Vehicle {vehicle_id} not found in SUMO yet, skipping...")
                        return False
            
            # Check if vehicle has a PDA
            async with session.get(f"{API_BASE_URL}/vehicle-info/{vehicle_id}") as response:
                if response.status == 200:
                    vehicle_info = await response.json()
                    has_pda = vehicle_info.get("pda_joined", False)
                    balance = vehicle_info.get("balance", 0)
                    
                    if balance < 0.002:
                        print(f"⚠️ Warning: {vehicle_id} has low balance: {balance} SOL")
                    
                    # If no PDA, join one
                    if not has_pda:
                        print(f"🔄 {vehicle_id} has no PDA, attempting to join...")
                        start_time = time.time()
                        async with session.post(f"{API_BASE_URL}/join-pda/{vehicle_id}") as join_response:
                            if join_response.status == 200:
                                end_time = time.time()
                                latency = end_time - start_time
                                join_data = await join_response.json()
                                
                                # Track PDA join latency
                                monitoring_data["transaction_latency"]["pda_join"].append({
                                    "timestamp": datetime.now().isoformat(),
                                    "vehicle_id": vehicle_id,
                                    "latency": latency,
                                    "success": join_data.get("status") == "joined"
                                })
                                
                                if join_data.get("status") == "joined":
                                    print(f"✅ {vehicle_id} joined PDA: {join_data.get('pda')} (latency: {latency:.3f}s)")
                                else:
                                    print(f"⚠️ Join attempt response: {join_data}")
                            else:
                                end_time = time.time()
                                latency = end_time - start_time
                                
                                # Still track the failed join latency
                                monitoring_data["transaction_latency"]["pda_join"].append({
                                    "timestamp": datetime.now().isoformat(),
                                    "vehicle_id": vehicle_id,
                                    "latency": latency,
                                    "success": False,
                                    "error": f"HTTP {join_response.status}"
                                })
                                
                                print(f"❌ Failed to join PDA: {await join_response.text()}")
                    else:
                        print(f"ℹ️ {vehicle_id} already has a PDA")
            
            # Initialize tracking for this vehicle
            monitoring_data["active_vehicles"].add(vehicle_id)
            monitoring_data["sol_usage"][vehicle_id] = {
                "initial_balance": balance,
                "transactions": []
            }
            
            # Record when this vehicle was added
            vehicle_addition_times[vehicle_id] = datetime.now().isoformat()
            
            print(f"✅ Added {vehicle_id} to monitoring")
            return True
        
    except Exception as e:
        print(f"Error adding {vehicle_id} to monitoring: {e}")
        return False

async def trust_score_reader():
    """Read trust scores from file produced by the dedicated updater"""
    print(f"Starting trust score reader every {UPDATE_INTERVAL} seconds")
    update_cycle = 0
    
    while True:
        update_cycle += 1
        print(f"\n=== Trust Score Read Cycle #{update_cycle} ===")
        
        try:
            # Read trust score data from file
            with open("trust_score_data.json", 'r') as f:
                external_data = json.load(f)
            
            # Get new trust scores (ones we haven't seen before)
            existing_timestamps = {score["timestamp"] for score in monitoring_data["trust_scores"]}
            new_scores = [score for score in external_data["trust_scores"] 
                         if score["timestamp"] not in existing_timestamps]
            
            # Add new trust scores to our monitoring data
            if new_scores:
                monitoring_data["trust_scores"].extend(new_scores)
                print(f"Added {len(new_scores)} new trust scores from external updater")
                
                # Print sample of new scores
                if new_scores:
                    sample_size = min(3, len(new_scores))
                    print(f"Sample of new scores:")
                    for score in new_scores[-sample_size:]:
                        print(f"  {score['vehicle_id']}: {score['trust_score']} (latency: {score['latency']:.3f}s)")
            else:
                print("No new trust scores found")
            
            # Also update transaction latency data
            for tx_type, records in external_data["transaction_latency"].items():
                if tx_type not in monitoring_data["transaction_latency"]:
                    monitoring_data["transaction_latency"][tx_type] = []
                
                existing_tx_timestamps = {tx["timestamp"] for tx in monitoring_data["transaction_latency"][tx_type]}
                new_tx_records = [tx for tx in records if tx["timestamp"] not in existing_tx_timestamps]
                
                if new_tx_records:
                    monitoring_data["transaction_latency"][tx_type].extend(new_tx_records)
                    print(f"Added {len(new_tx_records)} new {tx_type} transaction records")
            
            # Print live evaluation stats
            try:
                print_live_stats()
            except Exception as stats_err:
                print(f"❌ Error printing stats: {stats_err}")
            
        except FileNotFoundError:
            print(f"❌ Trust score data file not found. Is the updater running?")
        except json.JSONDecodeError:
            print(f"❌ Error decoding trust score data file. It may be corrupted.")
        except Exception as e:
            print(f"❌ Error reading trust scores: {e}")
        
        # Wait for next read cycle
        await asyncio.sleep(UPDATE_INTERVAL)

async def platoon_join_requester():
    """Automatically request to join platoons when vehicles have valid trust scores"""
    print("Starting automatic platoon join requester")
    
    # Add monitoring stats
    join_stats = {
        "cycles": 0,
        "total_attempts": 0,
        "successful_joins": 0,
        "failed_joins": 0,
        "already_in_platoon": 0,
        "not_eligible": 0,
        "api_errors": 0
    }
    
    # Wait a bit before starting to let trust scores initialize
    await asyncio.sleep(30)

    while True:
        # Update monitoring cycle count
        join_stats["cycles"] += 1
        cycle_start_time = time.time()
        
        active_vehicles = list(monitoring_data["active_vehicles"])

        if not active_vehicles:
            print("No active vehicles for platoon joining yet")
        else:
            vehicles_to_check = random.sample(active_vehicles, min(5, len(active_vehicles)))
            print(f"\n🔍 Checking platoon eligibility for: {vehicles_to_check}")
            print(f"--- Join Cycle #{join_stats['cycles']} | {len(vehicles_to_check)}/{len(active_vehicles)} vehicles ---")

            semaphore = asyncio.Semaphore(3)

            async def try_join_platoon(vehicle_id):
                async with semaphore:
                    try:
                        async with get_session() as session:
                            # Step 1: Get vehicle info
                            async with session.get(f"{API_BASE_URL}/vehicle-info/{vehicle_id}") as response:
                                if response.status != 200:
                                    print(f"Error getting vehicle info for {vehicle_id}")
                                    join_stats["api_errors"] += 1
                                    return
                                vehicle_info = await response.json()

                                print(f"\n🚗 Vehicle {vehicle_id} info:")
                                print(f"  Trust score: {vehicle_info.get('trust_score', 'unknown')}")
                                print(f"  Platoon status: {vehicle_info.get('platoon_status', 'unknown')}")
                                print(f"  Can request join: {vehicle_info.get('can_request_join', False)}")
                                print(f"  PDA joined: {vehicle_info.get('pda_joined', False)}")
                                print(f"  Eligible RSUs: {vehicle_info.get('eligible_rsus', [])}")

                                # Step 2: Skip if already in a platoon
                                if "not_joined" not in vehicle_info.get("platoon_status", "not_joined"):
                                    print(f"  ➡️ Already in platoon, skipping")
                                    join_stats["already_in_platoon"] += 1
                                    return

                                # Step 3: Check eligibility
                                eligible_rsus = vehicle_info.get("eligible_rsus", [])
                                can_request_join = vehicle_info.get("can_request_join", False)

                                if not eligible_rsus or not can_request_join:
                                    print(f"  ❌ Not eligible to join any platoons")
                                    join_stats["not_eligible"] += 1
                                    return

                            # Step 4: Random RSU selection
                            chosen_rsu = random.choice(eligible_rsus)
                            rsu_id = chosen_rsu["rsu_id"]
                            threshold = chosen_rsu["threshold"]

                            print(f"  🔄 Attempting to join platoon {rsu_id} (threshold: {threshold})")
                            join_stats["total_attempts"] += 1
                            
                            # Step a: Track platoon join latency - Start timer
                            join_start_time = time.time()

                            # Step 5: Recheck malicious status before sending
                            async with session.get(f"{API_BASE_URL}/vehicle-info/{vehicle_id}") as recheck_response:
                                if recheck_response.status == 200:
                                    recheck_info = await recheck_response.json()
                                    if recheck_info.get("malicious_flag", False):
                                        print(f"  ❗ Vehicle became malicious — aborting join")
                                        return

                            # Step 6: Send join request to Flask route
                            async with session.post(f"{API_BASE_URL}/platoon-request/{vehicle_id}/{rsu_id}") as join_response:
                                # Calculate platoon join latency
                                join_latency = time.time() - join_start_time

                                # Track latency in monitoring data
                                monitoring_data["transaction_latency"]["platoon_join"].append({
                                    "timestamp": datetime.now().isoformat(),
                                    "vehicle_id": vehicle_id,
                                    "rsu_id": rsu_id,
                                    "latency": join_latency,
                                    "threshold": threshold
                                })

                                trust_score = next(
                                    (s["trust_score"] for s in reversed(monitoring_data["trust_scores"])
                                     if s["vehicle_id"] == vehicle_id), 0)

                                if join_response.status == 200:
                                    join_data = await join_response.json()
                                    success = "joined" in join_data.get("status", "")

                                    # Update transaction latency with success status
                                    monitoring_data["transaction_latency"]["platoon_join"][-1]["success"] = success

                                    event = {
                                        "timestamp": datetime.now().isoformat(),
                                        "event_type": "platoon_join_attempt",
                                        "vehicle_id": vehicle_id,
                                        "rsu_id": rsu_id,
                                        "success": success,
                                        "trust_score": trust_score,
                                        "threshold": threshold,
                                        "latency": join_latency  # Add latency to event data
                                    }
                                    monitoring_data["events"].append(event)

                                    if success:
                                        print(f"  ✅ Successfully joined platoon {rsu_id} (took {join_latency:.2f}s)")
                                        join_stats["successful_joins"] += 1
                                        
                                        # Track blockchain transaction cost
                                        if vehicle_id in monitoring_data["sol_usage"]:
                                            monitoring_data["sol_usage"][vehicle_id]["transactions"].append({
                                                "timestamp": datetime.now().isoformat(),
                                                "type": "platoon_join",
                                                "estimated_cost": 0.000008,  # 8000 lamports (bit more than trust update)
                                                "latency": join_latency
                                            })
                                    else:
                                        print(f"  ❌ Join failed (status unclear): {join_data}")
                                        join_stats["failed_joins"] += 1
                                else:
                                    # Update transaction latency with failure status
                                    monitoring_data["transaction_latency"]["platoon_join"][-1]["success"] = False
                                    monitoring_data["transaction_latency"]["platoon_join"][-1]["error"] = f"HTTP {join_response.status}"
                                    
                                    error_text = await join_response.text()
                                    print(f"  ❌ Join request failed: {join_response.status}")
                                    print(f"  ❌ Error: {error_text}")
                                    join_stats["failed_joins"] += 1

                    except Exception as e:
                        print(f"Error in platoon join request for {vehicle_id}: {e}")
                        join_stats["api_errors"] += 1

            # Run concurrently
            join_tasks = [try_join_platoon(vid) for vid in vehicles_to_check]
            await asyncio.gather(*join_tasks)
            
            # Print cycle summary
            cycle_duration = time.time() - cycle_start_time
            print("\n=== PLATOON JOIN CYCLE STATS ===")
            print(f"Cycle #{join_stats['cycles']} completed in {cycle_duration:.2f} seconds")
            print(f"Total join attempts: {join_stats['total_attempts']}")
            print(f"Success rate: {(join_stats['successful_joins'] / max(join_stats['total_attempts'], 1)) * 100:.1f}%")
            print(f"Vehicles already in platoons: {join_stats['already_in_platoon']}")
            print(f"Vehicles not eligible: {join_stats['not_eligible']}")
            print(f"API errors: {join_stats['api_errors']}")
            
            # Calculate latency statistics if we have data
            platoon_join_latencies = [entry["latency"] for entry in monitoring_data["transaction_latency"]["platoon_join"] if "latency" in entry]
            if platoon_join_latencies:
                avg_latency = sum(platoon_join_latencies) / len(platoon_join_latencies)
                max_latency = max(platoon_join_latencies)
                min_latency = min(platoon_join_latencies)
                print(f"Avg join latency: {avg_latency:.3f}s (min: {min_latency:.3f}s, max: {max_latency:.3f}s)")
            
            print("================================\n")

        # Wait before next round
        await asyncio.sleep(20)

# Vehicle metadata tracking
vehicle_metadata = {}

async def process_malicious_leave_queue():
    """Process queued leave operations for malicious vehicles"""
    # Ensure vehicle_metadata is available
    global vehicle_metadata
    
    while True:
        for vehicle_id, metadata in vehicle_metadata.items():
            if metadata.get("leave_queued", False) and metadata.get("platoon_status", "").startswith("joined_"):
                print(f"🔴 Processing queued leave for malicious vehicle {vehicle_id}")
                try:
                    # Call the leave platoon API
                    response = requests.post(f"{API_BASE_URL}/leave-platoon/{vehicle_id}")
                    if response.status_code == 200:
                        print(f"✅ Malicious vehicle {vehicle_id} successfully left platoon")
                        # Reset the queue flag
                        vehicle_metadata[vehicle_id]["leave_queued"] = False
                    else:
                        print(f"❌ Failed to process leave for {vehicle_id}: {response.status_code}")
                except Exception as e:
                    print(f"❌ Error processing leave for {vehicle_id}: {e}")
        
        # Check every 15 seconds
        await asyncio.sleep(15)

async def platoon_monitor():
    """Monitor platoons with connection pooling and more efficient checks"""
    print("Starting platoon membership monitor")
    
    # Wait a bit before starting monitoring
    await asyncio.sleep(20)
    
    while True:
        # Get RSUs using session
        try:
            async with get_session() as session:
                async with session.get(f"{API_BASE_URL}/realtime-vehicle-data") as response:
                    if response.status == 200:
                        data = await response.json()
                        rsu_ids = list(data.get("rsus", {}).keys())
                        
                        if not rsu_ids:
                            print("No RSUs found. Using default RSUs...")
                            rsu_ids = ["RSU_1", "RSU_2"]
                    else:
                        print(f"Error getting RSUs: {response.status}")
                        rsu_ids = ["RSU_1", "RSU_2"]
                
                # Check each RSU
                for rsu_id in rsu_ids:
                    try:
                        # Get platoon info
                        async with session.get(f"{API_BASE_URL}/platoon-info/{rsu_id}") as response:
                            if response.status != 200:
                                continue
                                
                            platoon_info = await response.json()
                            
                            threshold = platoon_info.get("threshold", 70)
                            members = platoon_info.get("members", [])
                            
                            # Store membership for tracking
                            current_members = [m["vehicle_id"] for m in members]
                            timestamp = datetime.now().isoformat()
                            
                            monitoring_data["platoon_memberships"][timestamp] = {
                                "rsu_id": rsu_id,
                                "members": current_members,
                                "threshold": threshold
                            }
                            
                            print(f"Platoon {rsu_id} has {len(members)} members with threshold {threshold}")
                            
                            # Just monitor for members below threshold without removing them
                            below_threshold_count = 0
                            for member in members:
                                vehicle_id = member["vehicle_id"]
                                trust_score = member.get("trust_score", 0)
                                
                                if trust_score < threshold:
                                    below_threshold_count += 1
                                    print(f"⚠️ {vehicle_id} score ({trust_score}) below threshold ({threshold})")
                                    print(f"   This vehicle should be automatically removed by the trust update system")
                                    
                                    # Log the observation without taking action
                                    event = {
                                        "timestamp": datetime.now().isoformat(),
                                        "event_type": "below_threshold_detected",
                                        "vehicle_id": vehicle_id,
                                        "rsu_id": rsu_id,
                                        "trust_score": trust_score,
                                        "threshold": threshold
                                    }
                                    monitoring_data["events"].append(event)
                            
                            if below_threshold_count > 0:
                                print(f"ℹ️ Found {below_threshold_count} vehicles below threshold in platoon {rsu_id}")
                    
                    except Exception as e:
                        print(f"Error monitoring platoon {rsu_id}: {e}")
                    
                    # Short delay between RSUs
                    await asyncio.sleep(1)
        
        except Exception as e:
            print(f"Error in platoon monitoring cycle: {e}")
        
        # Wait for next check cycle
        await asyncio.sleep(35)

        # Print live stats about platoons
        if monitoring_data["platoon_memberships"]:
            recent_memberships = list(monitoring_data["platoon_memberships"].values())[-min(5, len(monitoring_data["platoon_memberships"])):]
            platoon_sizes = {}
            for membership in recent_memberships:
                rsu = membership["rsu_id"]
                if rsu not in platoon_sizes:
                    platoon_sizes[rsu] = []
                platoon_sizes[rsu].append(len(membership["members"]))
            
            print("\n=== PLATOON STATS ===")
            for rsu, sizes in platoon_sizes.items():
                if sizes:
                    avg_size = sum(sizes) / len(sizes)
                    print(f"Platoon {rsu}: Avg size = {avg_size:.1f}, Current size = {sizes[-1]}")
            print("=====================\n")

async def run_monitoring(duration_seconds=50):
    """Run the complete monitoring system for the specified duration"""
    start_time = time.time()
    end_time = start_time + duration_seconds
    
    print(f"Starting automated monitoring for {duration_seconds} seconds...")
    
    # Malicious vehicle detection analysis function
    async def analyze_malicious_detection():
        """Periodically analyze malicious vehicle detection effectiveness"""
        print("Starting malicious vehicle detection analysis...")
        
        while True:
            try:
                # Get vehicle classifications
                vehicle_types = {}
                try:
                    response = requests.get(f"{API_BASE_URL}/vehicle-classification")
                    if response.status_code == 200:
                        data = response.json()
                        vehicle_types = data.get("vehicle_types", {})
                        
                        print(f"Found {len(vehicle_types)} classified vehicles:")
                        normal_count = sum(1 for v_type in vehicle_types.values() if v_type == 'normal')
                        malicious_count = sum(1 for v_type in vehicle_types.values() if v_type == 'malicious')
                        print(f"  - Normal: {normal_count}")
                        print(f"  - Malicious: {malicious_count}")
                except Exception as e:
                    print(f"Error fetching vehicle classifications: {e}")
                
                # Get flagged vehicles by checking their individual malicious flags
                flagged_vehicles = set()
                try:
                    # First, get all vehicle IDs from vehicle types dict
                    all_vehicles = list(vehicle_types.keys())
                    print(f"Checking malicious flags for {len(all_vehicles)} vehicles...")
                    
                    # Process in batches to avoid overwhelming the API
                    batch_size = 10
                    for i in range(0, len(all_vehicles), batch_size):
                        batch = all_vehicles[i:i+batch_size]
                        for vehicle_id in batch:
                            try:
                                response = requests.get(f"{API_BASE_URL}/vehicle-info/{vehicle_id}")
                                if response.status_code == 200:
                                    data = response.json()
                                    # Check if vehicle is flagged as malicious
                                    if data.get("pda_joined", False) and data.get("malicious_flag", False):
                                        flagged_vehicles.add(vehicle_id)
                                        print(f"🚩 Vehicle {vehicle_id} is flagged as malicious")
                            except Exception as vehicle_err:
                                print(f"Error checking vehicle {vehicle_id}: {vehicle_err}")
                            
                    print(f"Found {len(flagged_vehicles)} vehicles flagged as malicious")
                except Exception as e:
                    print(f"Error fetching flagged vehicles: {e}")
                
                # Calculate confusion matrix
                detection_stats = {
                    "true_positives": 0,
                    "false_positives": 0,
                    "true_negatives": 0,
                    "false_negatives": 0
                }
                
                for vehicle_id, vehicle_type in vehicle_types.items():
                    is_malicious = vehicle_type == "malicious"
                    is_flagged = vehicle_id in flagged_vehicles
                    
                    if is_malicious and is_flagged:
                        detection_stats["true_positives"] += 1
                    elif not is_malicious and is_flagged:
                        detection_stats["false_positives"] += 1
                    elif not is_malicious and not is_flagged:
                        detection_stats["true_negatives"] += 1
                    elif is_malicious and not is_flagged:
                        detection_stats["false_negatives"] += 1
                
                # Calculate performance metrics
                total = sum(detection_stats.values())
                if total > 0:
                    print("\n=== MALICIOUS VEHICLE DETECTION ===")
                    print(f"Total vehicles analyzed: {total}")
                    print(f"True positives: {detection_stats['true_positives']}")
                    print(f"False positives: {detection_stats['false_positives']}")
                    print(f"True negatives: {detection_stats['true_negatives']}")
                    print(f"False negatives: {detection_stats['false_negatives']}")
                    
                    precision = detection_stats["true_positives"] / (detection_stats["true_positives"] + detection_stats["false_positives"]) if (detection_stats["true_positives"] + detection_stats["false_positives"]) > 0 else 0
                    recall = detection_stats["true_positives"] / (detection_stats["true_positives"] + detection_stats["false_negatives"]) if (detection_stats["true_positives"] + detection_stats["false_negatives"]) > 0 else 0
                    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                    
                    print(f"Precision: {precision:.4f}")
                    print(f"Recall: {recall:.4f}")
                    print(f"F1 score: {f1:.4f}")
                    print("=====================================\n")
                
            except Exception as e:
                print(f"Error in malicious detection analysis: {e}")
            
            # Wait before next analysis
            await asyncio.sleep(15)
    
    # Trust volatility analysis function
    async def analyze_trust_volatility():
        """Analyze the differences in trust score volatility between normal and malicious vehicles"""
        print("Starting trust score volatility analysis...")
        
        while True:
            try:
                # Get vehicle types
                vehicle_types = {}
                try:
                    response = requests.get(f"{API_BASE_URL}/vehicle-classification")
                    if response.status_code == 200:
                        data = response.json()
                        vehicle_types = data.get("vehicle_types", {})
                except Exception as e:
                    print(f"Error fetching vehicle classifications for volatility: {e}")
                
                if not vehicle_types:
                    print("No vehicle types available for volatility analysis yet")
                    await asyncio.sleep(15)
                    continue
                
                # Calculate trust score volatility for each vehicle
                volatility_by_type = {"normal": [], "malicious": []}
                
                for vehicle_id, vehicle_type in vehicle_types.items():
                    # Get trust score history for this vehicle
                    vehicle_scores = [s for s in monitoring_data["trust_scores"] if s["vehicle_id"] == vehicle_id]
                    
                    if len(vehicle_scores) < 2:
                        continue  # Skip vehicles with insufficient data
                    
                    # Calculate differences between consecutive scores
                    diffs = []
                    for i in range(1, len(vehicle_scores)):
                        diff = abs(vehicle_scores[i]["trust_score"] - vehicle_scores[i-1]["trust_score"])
                        diffs.append(diff)
                    
                    if diffs:
                        avg_change = sum(diffs) / len(diffs)
                        volatility_by_type[vehicle_type].append(avg_change)
                
                # Print volatility statistics
                if volatility_by_type["normal"] and volatility_by_type["malicious"]:
                    avg_normal = sum(volatility_by_type["normal"]) / len(volatility_by_type["normal"])
                    avg_malicious = sum(volatility_by_type["malicious"]) / len(volatility_by_type["malicious"])
                    ratio = avg_malicious / avg_normal if avg_normal > 0 else 0
                    
                    print("\n=== TRUST SCORE VOLATILITY ANALYSIS ===")
                    print(f"Normal vehicles: {len(volatility_by_type['normal'])}")
                    print(f"Malicious vehicles: {len(volatility_by_type['malicious'])}")
                    print(f"Average normal volatility: {avg_normal:.4f}")
                    print(f"Average malicious volatility: {avg_malicious:.4f}")
                    print(f"Volatility ratio (M:N): {ratio:.4f}x")
                    print("========================================\n")
            
            except Exception as e:
                print(f"Error in trust volatility analysis: {e}")
            
            # Wait before next analysis
            await asyncio.sleep(20)
    
    # Set up the monitoring tasks
    tasks = [
        add_vehicles_over_time(duration_seconds),  # This should run for the full duration
        trust_score_reader(),  # This runs until canceled
        platoon_join_requester(),  # This runs until canceled, but with initial delay
        platoon_monitor(),  # This runs until canceled, but with initial delay
        analyze_malicious_detection(),  # This runs until canceled
        analyze_trust_volatility(),  # This runs until canceled
        process_malicious_leave_queue()  # This runs until canceled
    ]
    
    # Create task to manage timeouts and task cancellation
    async def monitor_time():
        """Monitor execution time and gracefully cancel tasks when duration is reached"""
        try:
            remaining = end_time - time.time()
            while remaining > 0:
                print(f"⏱️ Monitoring will continue for {remaining:.1f} more seconds")
                
                # Wait for shorter intervals to be more responsive
                await asyncio.sleep(min(10, remaining))
                remaining = end_time - time.time()
            
            print("⏱️ Time's up! Stopping all monitoring tasks...")
            return
            
        except Exception as e:
            print(f"❌ Error in time monitor: {e}")
    
    # Run until duration expires
    try:
        # Create task group and monitor
        task_group = asyncio.gather(*tasks)
        
        # Wait until monitoring duration is reached
        await monitor_time()
        
        # Cancel all tasks
        print("🛑 Cancelling all monitoring tasks...")
        task_group.cancel()
        
        try:
            await task_group
        except asyncio.CancelledError:
            print("📊 Monitoring tasks successfully cancelled")
    
    except Exception as e:
        print(f"❌ Error during monitoring: {e}")
    
    # Generate report and visualizations
    print("📈 Generating final report and visualizations...")
    generate_monitoring_report(duration_seconds)
    
    # Close any open sessions
    global session
    if session:
        await session.close()
        session = None
    
    print("✅ Monitoring complete!")

def generate_monitoring_report(duration_seconds):
    """Generate analysis and visualizations from the monitoring data"""
    print("Generating monitoring report...")
    
    # Convert trust score data to DataFrame for analysis
    trust_df = pd.DataFrame(monitoring_data["trust_scores"])
    if trust_df.empty:
        print("No trust score data collected!")
        return
    
    trust_df['timestamp'] = pd.to_datetime(trust_df['timestamp'])
    
    # Create events DataFrame
    events_df = pd.DataFrame(monitoring_data["events"])
    if not events_df.empty:
        events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
    
    # Create vehicle addition timeline
    vehicle_timeline = pd.DataFrame([
        {"timestamp": time, "vehicle_id": v_id}
        for v_id, time in vehicle_addition_times.items()
    ])
    if not vehicle_timeline.empty:
        vehicle_timeline['timestamp'] = pd.to_datetime(vehicle_timeline['timestamp'])
    
    # Create membership timeline
    membership_data = []
    for timestamp, data in monitoring_data["platoon_memberships"].items():
        for vehicle_id in data["members"]:
            membership_data.append({
                "timestamp": timestamp,
                "rsu_id": data["rsu_id"],
                "vehicle_id": vehicle_id
            })
    
    membership_df = pd.DataFrame(membership_data)
    if not membership_df.empty:
        membership_df['timestamp'] = pd.to_datetime(membership_df['timestamp'])
    
    # Calculate SOL usage
    sol_usage = []
    for vehicle_id, data in monitoring_data["sol_usage"].items():
        total_cost = sum(tx["estimated_cost"] for tx in data["transactions"])
        transaction_count = len(data["transactions"])
        
        sol_usage.append({
            "vehicle_id": vehicle_id,
            "total_cost": total_cost,
            "transaction_count": transaction_count,
            "avg_cost_per_tx": total_cost / transaction_count if transaction_count > 0 else 0
        })
    
    sol_df = pd.DataFrame(sol_usage)
    
    # Fetch vehicle type classifications
    try:
        response = requests.get(f"{API_BASE_URL}/vehicle-classification")
        if response.status_code == 200:
            data = response.json()
            vehicle_types = data.get("vehicle_types", {})
        else:
            print(f"Warning: Could not fetch vehicle classifications, status code: {response.status_code}")
            vehicle_types = {}
    except Exception as e:
        print(f"Error fetching vehicle classifications: {e}")
        vehicle_types = {}
    
    # Get malicious vehicle flags from platoons
    flagged_vehicles = set()
    for rsu_id in ["RSU_1", "RSU_2"]:
        try:
            response = requests.get(f"{API_BASE_URL}/platoon-info/{rsu_id}")
            if response.status_code == 200:
                data = response.json()
                for member in data.get("malicious_members", []):
                    flagged_vehicles.add(member.get("vehicle_id"))
        except Exception as e:
            print(f"Error fetching flagged vehicles from {rsu_id}: {e}")
    
    # Calculate confusion matrix
    detection_stats = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0
    }
    
    for vehicle_id, vehicle_type in vehicle_types.items():
        is_malicious = vehicle_type == "malicious"
        is_flagged = vehicle_id in flagged_vehicles
        
        if is_malicious and is_flagged:
            detection_stats["true_positives"] += 1
        elif not is_malicious and is_flagged:
            detection_stats["false_positives"] += 1
        elif not is_malicious and not is_flagged:
            detection_stats["true_negatives"] += 1
        elif is_malicious and not is_flagged:
            detection_stats["false_negatives"] += 1
    
    # Create visualizations
    create_visualizations(trust_df, events_df, vehicle_timeline, membership_df, sol_df, 
                          vehicle_types, flagged_vehicles, detection_stats)
    
    # Generate summary statistics
    generate_summary_statistics(trust_df, events_df, sol_usage, vehicle_types, 
                               flagged_vehicles, detection_stats)

def create_visualizations(trust_df, events_df, vehicle_timeline, membership_df, sol_df, 
                          vehicle_types, flagged_vehicles, detection_stats):
    """Create and save visualizations for monitoring report"""
    # 1. Vehicle Addition Over Time
    if not vehicle_timeline.empty:
        plt.figure(figsize=(12, 6))
        vehicle_counts = vehicle_timeline.groupby(pd.Grouper(key='timestamp', freq='1min')).count()
        vehicle_counts['cumulative'] = vehicle_counts['vehicle_id'].cumsum()
        
        plt.plot(vehicle_counts.index, vehicle_counts['cumulative'], 
                marker='o', markersize=5, linestyle='-', linewidth=2)
        plt.title("Vehicles Added Over Time")
        plt.xlabel("Time")
        plt.ylabel("Cumulative Vehicle Count")
        plt.grid(True)
        plt.savefig("vehicle_addition.png")
        plt.close()
    
    # 2. Trust Score Evolution
    plt.figure(figsize=(12, 6))
    
    # Get a subset of vehicles if there are too many
    vehicle_subset = list(set(trust_df['vehicle_id'].unique()))
    if len(vehicle_subset) > 10:
        vehicle_subset = random.sample(vehicle_subset, 10)
    
    for vehicle_id in vehicle_subset:
        vehicle_data = trust_df[trust_df['vehicle_id'] == vehicle_id]
        
        # Color based on vehicle type
        if vehicle_id in vehicle_types:
            color = 'green' if vehicle_types[vehicle_id] == "normal" else 'red'
            label = f"{vehicle_id} ({'N' if vehicle_types[vehicle_id] == 'normal' else 'M'})"
        else:
            color = 'blue'
            label = vehicle_id
            
        plt.plot(vehicle_data['timestamp'], vehicle_data['trust_score'], 
                 marker='o', markersize=3, linestyle='-', label=label, color=color)
    
    plt.title("Trust Score Evolution (Sample Vehicles)")
    plt.xlabel("Time")
    plt.ylabel("Trust Score")
    plt.legend()
    plt.grid(True)
    plt.savefig("trust_score_evolution.png")
    plt.close()
    
    # 3. Trust Score Distribution by Vehicle Type
    plt.figure(figsize=(12, 6))
    
    # Create separate dataframes for normal and malicious vehicles
    normal_data = []
    malicious_data = []
    
    for record in trust_df.to_dict('records'):
        vehicle_id = record.get("vehicle_id")
        if vehicle_id in vehicle_types:
            record_copy = record.copy()
            record_copy["vehicle_type"] = vehicle_types[vehicle_id]
            
            if vehicle_types[vehicle_id] == "normal":
                normal_data.append(record_copy)
            else:
                malicious_data.append(record_copy)
    
    normal_df = pd.DataFrame(normal_data)
    malicious_df = pd.DataFrame(malicious_data)
    
    if not normal_df.empty:
        normal_df['timestamp'] = pd.to_datetime(normal_df['timestamp'])
        normal_df['minute'] = normal_df['timestamp'].dt.floor('min')
        normal_stats = normal_df.groupby('minute')['trust_score'].mean()
        plt.plot(normal_stats.index, normal_stats, 'g-', linewidth=2, label='Normal Vehicles (avg)')
    
    if not malicious_df.empty:
        malicious_df['timestamp'] = pd.to_datetime(malicious_df['timestamp'])
        malicious_df['minute'] = malicious_df['timestamp'].dt.floor('min')
        malicious_stats = malicious_df.groupby('minute')['trust_score'].mean()
        plt.plot(malicious_stats.index, malicious_stats, 'r-', linewidth=2, label='Malicious Vehicles (avg)')
    
    # Add a threshold line
    plt.axhline(y=75, color='black', linestyle='--', alpha=0.7, label='Typical Threshold')
    
    plt.title("Trust Score Distribution by Vehicle Type")
    plt.xlabel("Time")
    plt.ylabel("Trust Score")
    plt.legend()
    plt.grid(True)
    plt.savefig("trust_score_by_type.png")
    plt.close()
    
    # 4. Create confusion matrix visualization
    plt.figure(figsize=(8, 6))
    
    confusion_matrix = [
        [detection_stats["true_negatives"], detection_stats["false_positives"]],
        [detection_stats["false_negatives"], detection_stats["true_positives"]]
    ]
    
    sns.heatmap(confusion_matrix, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Not Flagged', 'Flagged'],
                yticklabels=['Normal', 'Malicious'])
    
    plt.title('Malicious Vehicle Detection Confusion Matrix')
    plt.ylabel('Actual Type')
    plt.xlabel('Detection Result')
    plt.tight_layout()
    plt.savefig("malicious_detection_matrix.png")
    plt.close()
    
    # 5. Generate Platoon Membership Visualization
    if not membership_df.empty:
        plt.figure(figsize=(12, 6))
        membership_counts = membership_df.groupby([pd.Grouper(key='timestamp', freq='1min'), 'rsu_id']).count()
        membership_counts = membership_counts.unstack(level='rsu_id')
        
        # Flatten multi-index columns
        if isinstance(membership_counts.columns, pd.MultiIndex):
            membership_counts.columns = [col[1] for col in membership_counts.columns]
        
        # Plot each RSU's membership
        for rsu_id in membership_counts.columns:
            plt.plot(membership_counts.index, membership_counts[rsu_id], 
                    marker='o', markersize=4, linestyle='-', label=f"RSU {rsu_id}")
        
        plt.title("Platoon Membership Over Time")
        plt.xlabel("Time")
        plt.ylabel("Vehicle Count")
        plt.legend()
        plt.grid(True)
        plt.savefig("platoon_membership.png")
        plt.close()
    
    # 6. Generate SOL Usage Visualization
    if not sol_df.empty:
        plt.figure(figsize=(10, 6))
        
        # Top 10 vehicles by SOL usage
        top_vehicles = sol_df.sort_values(by='total_cost', ascending=False).head(10)
        
        bars = plt.bar(top_vehicles['vehicle_id'], top_vehicles['total_cost'])
        
        # Color bars by vehicle type if available
        for i, vehicle_id in enumerate(top_vehicles['vehicle_id']):
            if vehicle_id in vehicle_types:
                bars[i].set_color('red' if vehicle_types[vehicle_id] == 'malicious' else 'green')
        
        plt.title("SOL Usage by Top 10 Vehicles")
        plt.xlabel("Vehicle ID")
        plt.ylabel("Total SOL Cost")
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig("sol_usage.png")
        plt.close()
    
    # 7. Generate Transaction Latency Visualization 
    # Create dataframes for each transaction type
    latency_dfs = {}
    for tx_type, records in monitoring_data["transaction_latency"].items():
        if records:
            df = pd.DataFrame(records)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            latency_dfs[tx_type] = df
    
    if latency_dfs:
        plt.figure(figsize=(12, 6))
        
        for tx_type, df in latency_dfs.items():
            if 'latency' in df.columns and not df.empty:
                df['minute'] = df['timestamp'].dt.floor('min')
                avg_latency = df.groupby('minute')['latency'].mean()
                
                plt.plot(avg_latency.index, avg_latency.values, 
                        marker='o', markersize=3, label=tx_type.replace('_', ' ').title())
        
        plt.title("Transaction Latency Over Time")
        plt.xlabel("Time")
        plt.ylabel("Latency (seconds)")
        plt.legend()
        plt.grid(True)
        plt.savefig("transaction_latency.png")
        plt.close()
    
    print("Visualizations created and saved successfully.")

def generate_summary_statistics(trust_df, events_df, sol_usage, vehicle_types, 
                              flagged_vehicles, detection_stats):
    """Generate and save summary statistics for the monitoring session"""
    summary = {
        "total_monitoring_duration_seconds": int(MONITORING_DURATION),
        "total_vehicles_added": int(len(vehicle_addition_times)),
        "total_trust_updates": int(len(trust_df)),
        "vehicles_monitored": int(len(trust_df['vehicle_id'].unique())),
        "avg_trust_score": float(trust_df['trust_score'].mean()),
        "min_trust_score": float(trust_df['trust_score'].min()),
        "max_trust_score": float(trust_df['trust_score'].max()),
        "sol_usage_total": float(sum(v["total_cost"] for v in sol_usage)),
        "sol_usage_avg_per_vehicle": float(sum(v["total_cost"] for v in sol_usage) / len(sol_usage) if sol_usage else 0),
        
        # Vehicle type statistics
        "normal_vehicles": len([v for v in vehicle_types.values() if v == "normal"]),
        "malicious_vehicles": len([v for v in vehicle_types.values() if v == "malicious"]),
        "flagged_vehicles": len(flagged_vehicles),
        
        # Detection statistics
        "true_positives": detection_stats["true_positives"],
        "false_positives": detection_stats["false_positives"],
        "true_negatives": detection_stats["true_negatives"],
        "false_negatives": detection_stats["false_negatives"],
    }
    
    # Calculate detection performance metrics
    total_malicious = detection_stats["true_positives"] + detection_stats["false_negatives"]
    total_normal = detection_stats["true_negatives"] + detection_stats["false_positives"]
    
    if total_malicious > 0:
        recall = detection_stats["true_positives"] / total_malicious
        summary["recall"] = float(recall)
    
    if detection_stats["true_positives"] + detection_stats["false_positives"] > 0:
        precision = detection_stats["true_positives"] / (detection_stats["true_positives"] + detection_stats["false_positives"])
        summary["precision"] = float(precision)
    
    if "precision" in summary and "recall" in summary and summary["precision"] + summary["recall"] > 0:
        f1_score = 2 * summary["precision"] * summary["recall"] / (summary["precision"] + summary["recall"])
        summary["f1_score"] = float(f1_score)
    
    # Add other stats from events
    if not events_df.empty:
        platoon_join_attempts = len(events_df[events_df['event_type'] == 'platoon_join_attempt'])
        successful_joins = len(events_df[(events_df['event_type'] == 'platoon_join_attempt') & 
                                         (events_df['success'] == True)])
        platoon_removals = len(events_df[events_df['event_type'] == 'platoon_removal'])
        below_threshold_counts = len(events_df[events_df['event_type'] == 'below_threshold_detected'])
        
        summary.update({
            "platoon_join_attempts": int(platoon_join_attempts),
            "successful_joins": int(successful_joins),
            "join_success_rate": float(successful_joins / platoon_join_attempts) if platoon_join_attempts > 0 else 0,
            "platoon_removals": int(platoon_removals),
            "below_threshold_detected": int(below_threshold_counts)
        })
    
    # Add latency statistics for each transaction type
    for tx_type, records in monitoring_data["transaction_latency"].items():
        if records:
            df = pd.DataFrame(records)
            if 'latency' in df.columns and not df.empty:
                summary.update({
                    f"{tx_type}_avg_latency": float(df['latency'].mean()),
                    f"{tx_type}_median_latency": float(df['latency'].median()),
                    f"{tx_type}_min_latency": float(df['latency'].min()),
                    f"{tx_type}_max_latency": float(df['latency'].max()),
                })
                if 'success' in df.columns:
                    summary.update({
                        f"{tx_type}_success_rate": float((df['success'].sum() / len(df)) * 100)
                    })
    
    # Save summary to JSON
    with open("monitoring_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    
    # Save serializable monitoring data
    serializable_data = {
        "trust_scores": monitoring_data["trust_scores"][:1000],  # Limit to first 1000 records
        "events": monitoring_data["events"],
        "vehicle_types": vehicle_types,
        "flagged_vehicles": list(flagged_vehicles),
        "detection_stats": detection_stats,
        "sol_usage": {vid: {"initial_balance": float(data["initial_balance"]), 
                         "transaction_count": int(len(data["transactions"])),
                         "total_cost": float(sum(tx["estimated_cost"] for tx in data["transactions"]))} 
                  for vid, data in monitoring_data["sol_usage"].items()},
        "transaction_latency": {tx_type: records[:500] for tx_type, records in monitoring_data["transaction_latency"].items()}
    }
    
    with open("monitoring_data.json", "w") as f:
        json.dump(serializable_data, f)
    
    print("\n=== MONITORING SUMMARY ===")
    print(f"Total Vehicles: {len(vehicle_types)}")
    print(f"  - Normal Vehicles: {summary['normal_vehicles']}")
    print(f"  - Malicious Vehicles: {summary['malicious_vehicles']}")
    print(f"  - Flagged Vehicles: {len(flagged_vehicles)}")
    
    print("\n=== MALICIOUS DETECTION PERFORMANCE ===")
    print(f"True Positives: {detection_stats['true_positives']}")
    print(f"False Positives: {detection_stats['false_positives']}")
    print(f"True Negatives: {detection_stats['true_negatives']}")
    print(f"False Negatives: {detection_stats['false_negatives']}")
    
    if "precision" in summary:
        print(f"Precision: {summary['precision']:.4f}")
    if "recall" in summary:
        print(f"Recall: {summary['recall']:.4f}")
    if "f1_score" in summary:
        print(f"F1 Score: {summary['f1_score']:.4f}")
    
    print("\nReport generated. Visualizations and data saved to disk.")

def analyze_transaction_success_rates():
    """Analyze success rates for different transaction types"""
    print("Analyzing transaction success rates...")
    
    # Calculate success rates per operation type
    success_rates = {}
    for tx_type, records in monitoring_data["transaction_latency"].items():
        if records:
            success_count = sum(1 for r in records if r.get("success", False))
            total_count = len(records)
            success_rates[tx_type] = {
                "success_count": success_count,
                "total_count": total_count,
                "rate": (success_count / total_count) * 100 if total_count > 0 else 0
            }
    
    return success_rates

def analyze_sol_cost_distribution():
    """Analyze and visualize SOL cost distribution by operation type"""
    print("Analyzing SOL cost distribution...")
    
    # Aggregate costs by operation type
    cost_by_type = {}
    transaction_counts = {}
    
    for vehicle_id, data in monitoring_data["sol_usage"].items():
        for tx in data["transactions"]:
            tx_type = tx["type"]
            cost = tx["estimated_cost"]
            
            # Add to cost totals
            cost_by_type[tx_type] = cost_by_type.get(tx_type, 0) + cost
            
            # Count transactions
            transaction_counts[tx_type] = transaction_counts.get(tx_type, 0) + 1
    
    # Calculate cost per transaction
    cost_per_tx = {tx_type: cost_by_type[tx_type] / transaction_counts[tx_type] 
                  for tx_type in cost_by_type.keys()}
    
    total_cost = sum(cost_by_type.values())
    
    return {"total_cost": total_cost, "cost_by_type": cost_by_type, 
            "transaction_counts": transaction_counts, "cost_per_tx": cost_per_tx}

def analyze_performance_under_load():
    """Analyze how performance changes with increasing number of vehicles"""
    print("Analyzing performance under load...")
    
    # Create DataFrame with timestamps of all transactions
    all_tx_records = []
    for tx_type, records in monitoring_data["transaction_latency"].items():
        for record in records:
            if "timestamp" in record and "latency" in record:
                record_copy = record.copy()
                record_copy["tx_type"] = tx_type
                all_tx_records.append(record_copy)
    
    if not all_tx_records:
        print("No transaction records available for load analysis")
        return None
    
    tx_df = pd.DataFrame(all_tx_records)
    tx_df["timestamp"] = pd.to_datetime(tx_df["timestamp"])
    tx_df = tx_df.sort_values("timestamp")
    
    # Count active vehicles at each timestamp
    active_vehicles_at_time = {}
    for timestamp in tx_df["timestamp"].unique():
        timestamp_str = timestamp.isoformat()
        # Count vehicles added before or at this timestamp
        active_count = sum(1 for v_time in vehicle_addition_times.values() 
                          if v_time <= timestamp_str)
        active_vehicles_at_time[timestamp] = active_count
    
    # Add vehicle count to each transaction record
    tx_df["active_vehicles"] = tx_df["timestamp"].map(active_vehicles_at_time)
    
    # Group by vehicle count and calculate average latency
    latency_by_load = tx_df.groupby("active_vehicles")["latency"].agg(["mean", "median", "count"]).reset_index()
    
    # Calculate throughput (transactions per second) over time
    tx_df["minute"] = tx_df["timestamp"].dt.floor('1min')
    throughput = tx_df.groupby("minute").size().reset_index()
    throughput.columns = ["minute", "tx_count"]
    throughput["throughput"] = throughput["tx_count"] / 60  # Transactions per second
    
    return {
        "latency_by_load": latency_by_load.to_dict(),
        "throughput": throughput.to_dict(),
    }

def analyze_resource_consumption():
    """Analyze resource consumption trends over time"""
    print("Analyzing resource consumption trends...")
    
    # Create time series of cumulative SOL usage
    sol_usage_over_time = []
    
    for vehicle_id, data in monitoring_data["sol_usage"].items():
        for tx in data["transactions"]:
            if "timestamp" in tx and "estimated_cost" in tx:
                sol_usage_over_time.append({
                    "timestamp": tx["timestamp"],
                    "vehicle_id": vehicle_id,
                    "cost": tx["estimated_cost"],
                    "type": tx.get("type", "unknown")
                })
    
    if not sol_usage_over_time:
        print("No SOL usage data available for resource analysis")
        return None
    
    sol_df = pd.DataFrame(sol_usage_over_time)
    sol_df["timestamp"] = pd.to_datetime(sol_df["timestamp"])
    sol_df = sol_df.sort_values("timestamp")
    
    # Calculate cumulative SOL usage
    sol_df["cumulative_cost"] = sol_df["cost"].cumsum()
    
    # Calculate SOL usage by operation type
    sol_by_type = sol_df.groupby("type")["cost"].sum().reset_index()
    sol_by_type = sol_by_type.sort_values("cost", ascending=False)
    
    return {
        "total_sol_usage": sol_df["cost"].sum(),
        "sol_per_vehicle": sol_df["cost"].sum() / len(vehicle_addition_times) if vehicle_addition_times else 0,
        "sol_by_type": sol_by_type.to_dict()
    }

def analyze_vehicle_types():
    """Analyze detection effectiveness of normal vs malicious vehicles"""
    # Only import locally to prevent circular imports
    global vehicle_types
    
    # Fetch the latest classifications from our API
    try:
        response = requests.get(f"{API_BASE_URL}/vehicle-classification")
        if response.status_code == 200:
            data = response.json()
            vehicle_types = data.get("vehicle_types", {})
    except Exception as e:
        print(f"Error fetching vehicle classifications: {e}")
    
    # Get flagged vehicles from platoon info
    try:
        flagged_vehicles = set()
        for rsu_id in ["RSU_1", "RSU_2"]:
            response = requests.get(f"{API_BASE_URL}/platoon-info/{rsu_id}")
            if response.status_code == 200:
                data = response.json()
                for member in data.get("malicious_members", []):
                    flagged_vehicles.add(member.get("vehicle_id"))
    except Exception as e:
        print(f"Error fetching flagged vehicles: {e}")
        
    # Calculate confusion matrix
    detection_stats = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0
    }
    
    for vehicle_id, vehicle_type in vehicle_types.items():
        is_malicious = vehicle_type == "malicious"
        is_flagged = vehicle_id in flagged_vehicles
        
        if is_malicious and is_flagged:
            detection_stats["true_positives"] += 1
        elif not is_malicious and is_flagged:
            detection_stats["false_positives"] += 1
        elif not is_malicious and not is_flagged:
            detection_stats["true_negatives"] += 1
        elif is_malicious and not is_flagged:
            detection_stats["false_negatives"] += 1
    
    # Print analysis
    total = sum(detection_stats.values())
    if total > 0:
        precision = detection_stats["true_positives"] / (detection_stats["true_positives"] + detection_stats["false_positives"]) if (detection_stats["true_positives"] + detection_stats["false_positives"]) > 0 else 0
        recall = detection_stats["true_positives"] / (detection_stats["true_positives"] + detection_stats["false_negatives"]) if (detection_stats["true_positives"] + detection_stats["false_negatives"]) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        print("\n=== MALICIOUS VEHICLE DETECTION ANALYSIS ===")
        print(f"Total vehicles analyzed: {total}")
        print(f"True positives: {detection_stats['true_positives']}")
        print(f"False positives: {detection_stats['false_positives']}")
        print(f"True negatives: {detection_stats['true_negatives']}")
        print(f"False negatives: {detection_stats['false_negatives']}")
        print(f"Precision: {precision:.2f}")
        print(f"Recall: {recall:.2f}")
        print(f"F1 score: {f1:.2f}")
        print("===========================================\n")

# Main entry point
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Automated monitoring of vehicle trust and platoon dynamics")
    parser.add_argument("--duration", type=int, default=50, 
                        help="Monitoring duration in seconds (default: 50)")
    parser.add_argument("--update-interval", type=int, default=15, 
                        help="Trust score update interval in seconds (default: 15)")
    parser.add_argument("--vehicle-pattern", type=str, choices=["linear", "burst"], default="linear",
                        help="Vehicle addition pattern (linear or burst)")
    parser.add_argument("--max-vehicles", type=int, default=100,
                        help="Maximum number of vehicles to add during the test")
    parser.add_argument("--vehicle-prefix", type=str, default="veh",
                        help="Prefix for vehicle IDs (default: veh)")
    
    args = parser.parse_args()
    
    # Set global configuration
    UPDATE_INTERVAL = args.update_interval
    MONITORING_DURATION = args.duration
    MAX_VEHICLES = args.max_vehicles
    VEHICLE_ADDITION_PATTERN = args.vehicle_pattern
    VEHICLE_PREFIX = args.vehicle_prefix
    
    # Print configuration
    print(f"Starting monitoring with:")
    print(f"- Duration: {MONITORING_DURATION} seconds")
    print(f"- Update interval: {UPDATE_INTERVAL} seconds")
    print(f"- Max vehicles: {MAX_VEHICLES}")
    print(f"- Vehicle pattern: {VEHICLE_ADDITION_PATTERN}")
    
    # Run the monitoring system
    asyncio.run(run_monitoring(MONITORING_DURATION))