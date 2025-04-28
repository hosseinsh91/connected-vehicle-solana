"""
Continuous Trust Updater

This script continuously updates trust scores for vehicles in a simulation.
It prioritizes new vehicles and ensures each vehicle's score is updated at
regular intervals while avoiding server overload.
"""

import asyncio
import requests
import time
import json
from datetime import datetime
import aiohttp
from contextlib import asynccontextmanager
import argparse
import random

# Configuration
API_BASE_URL = "http://localhost:5002"
OUTPUT_FILE = "trust_score_data.json"
SCAN_INTERVAL = 3  # seconds between checks for new vehicles
MIN_UPDATE_INTERVAL = 5  # minimum seconds between updates for each vehicle
MAX_UPDATE_INTERVAL = 15  # maximum seconds between updates for each vehicle
MAX_CONCURRENT_UPDATES = 1  # Only update one vehicle at a time

# Connection pooling
session = None

@asynccontextmanager
async def get_session():
    """Get or create an aiohttp ClientSession with proper connection pooling."""
    global session
    if session is None:
        session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=5))
    try:
        yield session
    finally:
        pass  # Will close at end of program

# Data storage
trust_score_data = {
    "trust_scores": [],
    "transaction_latency": {
        "trust_update": []
    }
}

# Vehicle tracking
known_vehicles = set()
last_update_time = {}
update_in_progress = set()  # Track vehicles currently being updated

async def get_active_vehicles():
    """Get the current list of active vehicles"""
    try:
        async with get_session() as session:
            async with session.get(f"{API_BASE_URL}/realtime-vehicle-data", timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    vehicles = data.get("vehicles", {})
                    return list(vehicles.keys())
                else:
                    print(f"Error getting vehicle data: {response.status}")
                    return []
    except Exception as e:
        print(f"Error checking for active vehicles: {e}")
        return []

async def update_vehicle_trust(vehicle_id):
    """Update trust score for a single vehicle"""
    if vehicle_id in update_in_progress:
        print(f"⚠️ Update already in progress for {vehicle_id}, skipping")
        return False
    
    update_in_progress.add(vehicle_id)
    try:
        print(f"Updating trust score for {vehicle_id}...")
        
        start_time = time.time()
        update_url = f"{API_BASE_URL}/update-trust/{vehicle_id}"
        
        async with get_session() as session:
            async with session.post(update_url, timeout=15) as response:
                end_time = time.time()
                latency = end_time - start_time
                
                # Read the response content regardless of status code
                response_text = await response.text()
                
                print(f"Response for {vehicle_id}: Status={response.status}, Time={latency:.3f}s")
                
                if response.status == 200:
                    try:
                        data = json.loads(response_text)
                        trust_score = data.get("score", 0)
                        
                        if trust_score > 0:
                            # Record the update
                            trust_record = {
                                "timestamp": datetime.now().isoformat(),
                                "vehicle_id": vehicle_id,
                                "trust_score": trust_score,
                                "zkp_verified": data.get("zkp_verified", False),
                                "latency": latency
                            }
                            trust_score_data["trust_scores"].append(trust_record)
                            
                            # Add to latency tracking
                            latency_record = {
                                "timestamp": datetime.now().isoformat(),
                                "vehicle_id": vehicle_id,
                                "latency": latency,
                                "success": True
                            }
                            trust_score_data["transaction_latency"]["trust_update"].append(latency_record)
                            
                            # Update the last update time
                            last_update_time[vehicle_id] = time.time()
                            
                            print(f"✅ Updated {vehicle_id}: score={trust_score} (latency: {latency:.3f}s)")
                            
                            # Flag if malicious
                            if data.get("malicious_flag", False):
                                print(f"🚨 Vehicle {vehicle_id} is flagged as MALICIOUS with score {trust_score}")
                                
                            return True
                        else:
                            print(f"⚠️ Vehicle {vehicle_id} has score 0 - not recording")
                            last_update_time[vehicle_id] = time.time()
                            return True
                    except json.JSONDecodeError:
                        print(f"❌ Invalid JSON response for {vehicle_id}: {response_text}")
                        return False
                else:
                    print(f"❌ Failed to update {vehicle_id}: {response.status}")
                    print(f"Error response: {response_text}")
                    return False
    except asyncio.TimeoutError:
        print(f"⏱️ Timeout updating {vehicle_id}")
        return False
    except Exception as e:
        print(f"❌ Error updating {vehicle_id}: {e}")
        return False
    finally:
        # Always remove from in-progress set
        update_in_progress.discard(vehicle_id)

async def staggered_vehicle_updater():
    """Update vehicles one at a time with priority for new vehicles"""
    print("Starting staggered vehicle trust updater")
    
    while True:
        try:
            # Get current active vehicles
            active_vehicles = await get_active_vehicles()
            
            # Check for new vehicles
            new_vehicles = set(active_vehicles) - known_vehicles
            if new_vehicles:
                print(f"\n🆕 Detected {len(new_vehicles)} new vehicles: {new_vehicles}")
                known_vehicles.update(new_vehicles)
                
                # Initialize last update time for new vehicles
                for vehicle_id in new_vehicles:
                    # For new vehicles, we set last_update_time to 0 to give them highest priority
                    last_update_time[vehicle_id] = 0
            
            # First priority: Update any brand new vehicles that have never been updated
            # These will have last_update_time of 0
            next_vehicle = None
            
            # Look for new vehicles first (ones with last_update_time of 0)
            new_vehicle_candidates = [v for v in active_vehicles 
                                     if v not in update_in_progress 
                                     and last_update_time.get(v, 0) == 0]
            
            if new_vehicle_candidates:
                # If we have multiple new vehicles, just take the first one
                next_vehicle = new_vehicle_candidates[0]
                print(f"\n🔔 Prioritizing new vehicle {next_vehicle} for first update")
            else:
                # If no new vehicles, find the vehicle waiting the longest since last update
                current_time = time.time()
                longest_wait = MIN_UPDATE_INTERVAL  # Only consider vehicles waiting at least this long
                
                for vehicle_id in active_vehicles:
                    # Skip vehicles already being updated
                    if vehicle_id in update_in_progress:
                        continue
                        
                    # Calculate time since last update
                    time_since_update = current_time - last_update_time.get(vehicle_id, 0)
                    
                    # Find the vehicle waiting the longest
                    if time_since_update > longest_wait:
                        longest_wait = time_since_update
                        next_vehicle = vehicle_id
            
            # Update the chosen vehicle
            if next_vehicle:
                # Different message based on whether it's a new vehicle or not
                if last_update_time.get(next_vehicle, 0) == 0:
                    print(f"\n⭐ Updating new vehicle {next_vehicle} for the first time")
                else:
                    time_since = time.time() - last_update_time.get(next_vehicle, 0)
                    print(f"\n⏳ Updating vehicle {next_vehicle} (waited {time_since:.1f}s)")
                
                # Update the vehicle
                success = await update_vehicle_trust(next_vehicle)
                
                # Save data after update
                await save_data()
                
                # Add a small delay to ensure we don't hammer the server
                await asyncio.sleep(2)
            else:
                # No vehicles need updates right now
                print(f"\n✓ All vehicles up to date. Checking again in {SCAN_INTERVAL}s")
                await asyncio.sleep(SCAN_INTERVAL)
            
        except Exception as e:
            print(f"❌ Error in vehicle updater: {e}")
            await asyncio.sleep(5)  # Longer delay after error

async def save_data():
    """Save the trust score data to file for monitoring"""
    try:
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(trust_score_data, f)
    except Exception as e:
        print(f"❌ Error saving data: {e}")

async def run():
    """Run the staggered vehicle updater"""
    try:
        print("Starting Staggered Trust Score Updater")
        print(f"- Scanning for new vehicles every {SCAN_INTERVAL} seconds")
        print(f"- Updating each vehicle between {MIN_UPDATE_INTERVAL}-{MAX_UPDATE_INTERVAL} seconds")
        print(f"- Processing ONE vehicle at a time to avoid server overload")
        
        await staggered_vehicle_updater()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Saving final data...")
        await save_data()
    except Exception as e:
        print(f"Error in main loop: {e}")
    finally:
        # Close the session
        global session
        if session:
            await session.close()
            session = None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Staggered Trust Score Updater")
    parser.add_argument("--scan-interval", type=float, default=3.0, 
                        help="Interval between scans for new vehicles (seconds)")
    parser.add_argument("--min-update", type=float, default=5.0,
                        help="Minimum time between updates for each vehicle (seconds)")
    parser.add_argument("--max-update", type=float, default=15.0,
                        help="Maximum time between updates for each vehicle (seconds)")
    parser.add_argument("--output", type=str, default="trust_score_data.json",
                        help="Output file path")
    
    args = parser.parse_args()
    
    SCAN_INTERVAL = args.scan_interval
    MIN_UPDATE_INTERVAL = args.min_update
    MAX_UPDATE_INTERVAL = args.max_update
    OUTPUT_FILE = args.output
    
    asyncio.run(run())