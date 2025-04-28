import json
import time
import os
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from datetime import datetime
import argparse
import matplotlib.dates as mdates

# Configuration
INPUT_FILE = "trust_score_data.json"
OUTPUT_DIR = "monitoring_results"
MONITORING_INTERVAL = 30  # seconds

def load_data():
    """Load the combined data file"""
    try:
        with open(INPUT_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ File not found: {INPUT_FILE}")
        return None
    except json.JSONDecodeError:
        print(f"❌ Invalid JSON in file: {INPUT_FILE}")
        return None
    except Exception as e:
        print(f"❌ Error loading data: {e}")
        return None

def analyze_platoon_performance(data):
    """Analyze platoon join performance"""
    if not data or "join_attempts" not in data or not data["join_attempts"]:
        print("No join attempt data available")
        return None
    
    # Convert to DataFrame for analysis
    join_df = pd.DataFrame(data["join_attempts"])
    join_df["timestamp"] = pd.to_datetime(join_df["timestamp"])
    join_df["minute"] = join_df["timestamp"].dt.floor("1min")
    
    # Calculate success rate by minute
    success_by_minute = join_df.groupby("minute").agg({
        "success": ["count", "sum"]
    })
    success_by_minute.columns = ["attempts", "successes"]
    success_by_minute["success_rate"] = (success_by_minute["successes"] / success_by_minute["attempts"]) * 100
    
    # Calculate latency stats
    join_df["latency"] = pd.to_numeric(join_df["latency"], errors="coerce")
    latency_by_minute = join_df.groupby("minute")["latency"].agg(["mean", "median", "min", "max"]).reset_index()
    
    # Calculate join concurrency (attempts per minute)
    concurrency = join_df.groupby("minute").size().reset_index(name="concurrent_joins")
    
    # Merge data
    performance = pd.merge(success_by_minute.reset_index(), concurrency, on="minute")
    performance = pd.merge(performance, latency_by_minute, on="minute")
    
    return performance

def analyze_trust_score_evolution(data):
    """Analyze how trust scores evolve over time"""
    if not data or "trust_scores" not in data or not data["trust_scores"]:
        print("No trust score data available")
        return None
    
    # Convert to DataFrame for analysis
    trust_df = pd.DataFrame(data["trust_scores"])
    trust_df["timestamp"] = pd.to_datetime(trust_df["timestamp"])
    trust_df["minute"] = trust_df["timestamp"].dt.floor("1min")
    
    # Calculate trust score stats by minute
    trust_stats = trust_df.groupby(["minute", "vehicle_id"])["trust_score"].last().reset_index()
    
    # Calculate average and distribution by minute
    trust_by_minute = trust_stats.groupby("minute")["trust_score"].agg(["mean", "std", "min", "max", "count"]).reset_index()
    
    # Check if any vehicles are flagged as malicious
    malicious_vehicles = set()
    for vehicle_id, status in data.get("vehicle_status", {}).items():
        if status.get("malicious_flag", False):
            malicious_vehicles.add(vehicle_id)
    
    # Separate trust scores for normal vs malicious vehicles
    if malicious_vehicles:
        trust_stats["is_malicious"] = trust_stats["vehicle_id"].isin(malicious_vehicles)
        
        # Group by minute and malicious status
        trust_by_type = trust_stats.groupby(["minute", "is_malicious"])["trust_score"].mean().reset_index()
        
        # Pivot to get separate columns
        trust_by_type = trust_by_type.pivot(index="minute", columns="is_malicious", values="trust_score").reset_index()
        trust_by_type.columns = ["minute", "normal_trust", "malicious_trust"]
        
        # Fill NaN values
        trust_by_type = trust_by_type.fillna(method="ffill")
    else:
        trust_by_type = None
    
    return {
        "trust_by_minute": trust_by_minute,
        "trust_by_type": trust_by_type,
        "malicious_vehicles": list(malicious_vehicles)
    }

def analyze_sol_usage(data):
    """Analyze SOL usage patterns"""
    if not data or "sol_usage" not in data:
        print("No SOL usage data available")
        return None
    
    # Extract all transactions
    all_transactions = []
    for vehicle_id, usage in data["sol_usage"].items():
        for tx in usage.get("transactions", []):
            tx_copy = tx.copy()
            tx_copy["vehicle_id"] = vehicle_id
            all_transactions.append(tx_copy)
    
    if not all_transactions:
        return None
    
    # Convert to DataFrame
    tx_df = pd.DataFrame(all_transactions)
    tx_df["timestamp"] = pd.to_datetime(tx_df["timestamp"])
    tx_df["minute"] = tx_df["timestamp"].dt.floor("1min")
    
    # Calculate costs by minute and type
    cost_by_minute = tx_df.groupby("minute")["estimated_cost"].sum().reset_index()
    cost_by_type = tx_df.groupby("type")["estimated_cost"].sum().reset_index()
    
    # Calculate cost per vehicle
    vehicle_costs = {}
    for vehicle_id, usage in data["sol_usage"].items():
        vehicle_costs[vehicle_id] = usage.get("total_cost", 0)
    
    # Cost by minute and type
    cost_by_minute_type = tx_df.groupby(["minute", "type"])["estimated_cost"].sum().reset_index()
    cost_by_minute_type_pivot = cost_by_minute_type.pivot(index="minute", columns="type", values="estimated_cost").reset_index()
    
    return {
        "cost_by_minute": cost_by_minute,
        "cost_by_type": cost_by_type,
        "vehicle_costs": vehicle_costs,
        "cost_by_minute_type": cost_by_minute_type_pivot
    }

def analyze_latency_vs_load(data):
    """Analyze how system latency changes with load"""
    if not data or "transaction_latency" not in data:
        return None
    
    # Combine all latency data
    all_latency = []
    
    for tx_type, records in data["transaction_latency"].items():
        for record in records:
            if "timestamp" in record and "latency" in record:
                record_copy = record.copy()
                record_copy["tx_type"] = tx_type
                all_latency.append(record_copy)
    
    if not all_latency:
        return None
    
    # Convert to DataFrame
    latency_df = pd.DataFrame(all_latency)
    latency_df["timestamp"] = pd.to_datetime(latency_df["timestamp"])
    latency_df["minute"] = latency_df["timestamp"].dt.floor("1min")
    
    # Count transactions by minute (load)
    tx_count_by_minute = latency_df.groupby("minute").size().reset_index(name="tx_count")
    
    # Calculate average latency by minute and type
    latency_by_minute_type = latency_df.groupby(["minute", "tx_type"])["latency"].mean().reset_index()
    
    # Merge with tx count to get latency vs load
    latency_vs_load = pd.merge(latency_by_minute_type, tx_count_by_minute, on="minute")
    
    # Also get success rates by load
    if "success" in latency_df.columns:
        latency_df["success"] = latency_df["success"].fillna(False)
        success_by_minute_type = latency_df.groupby(["minute", "tx_type"]).agg({
            "success": ["count", lambda x: x.sum()]
        }).reset_index()
        success_by_minute_type.columns = ["minute", "tx_type", "attempts", "successes"]
        success_by_minute_type["success_rate"] = (success_by_minute_type["successes"] / success_by_minute_type["attempts"]) * 100
        
        # Merge with tx count
        success_vs_load = pd.merge(success_by_minute_type, tx_count_by_minute, on="minute")
    else:
        success_vs_load = None
    
    return {
        "latency_vs_load": latency_vs_load,
        "success_vs_load": success_vs_load
    }


def analyze_malicious_detection(data):
    """Analyze malicious vehicle detection effectiveness"""
    if not data or "vehicle_status" not in data:
        return None
    
    # First, identify which vehicles are malicious according to status
    malicious_vehicles = set()
    flagged_vehicles = set()
    
    for vehicle_id, status in data.get("vehicle_status", {}).items():
        # Check if vehicle is marked as malicious in status
        if status.get("malicious_flag", False):
            flagged_vehicles.add(vehicle_id)
    
    # Try to get actual malicious status from trust score evolution
    # Look for consistent low trust scores or rapid decreases
    if "trust_scores" in data and data["trust_scores"]:
        trust_df = pd.DataFrame(data["trust_scores"])
        trust_df["timestamp"] = pd.to_datetime(trust_df["timestamp"])
        
        # Group by vehicle_id and get last few scores
        last_scores = {}
        for vehicle_id in data.get("active_vehicles", []):
            vehicle_scores = trust_df[trust_df["vehicle_id"] == vehicle_id]["trust_score"].tolist()
            if len(vehicle_scores) >= 3:
                last_scores[vehicle_id] = vehicle_scores[-3:]
        
        # Identify potentially malicious vehicles based on trust score patterns
        for vehicle_id, scores in last_scores.items():
            # Method 1: Very low trust score
            if any(score < 50 for score in scores):
                malicious_vehicles.add(vehicle_id)
            
            # Method 2: Rapid decrease in trust score
            if len(scores) >= 2:
                decreases = [scores[i] - scores[i+1] for i in range(len(scores)-1)]
                if any(decrease > 15 for decrease in decreases):
                    malicious_vehicles.add(vehicle_id)
    
    # If we don't have malicious vehicles identified through trust patterns, 
    # use the flagged vehicles as our ground truth
    if not malicious_vehicles and flagged_vehicles:
        malicious_vehicles = flagged_vehicles
    
    # Calculate confusion matrix
    true_positives = len(malicious_vehicles.intersection(flagged_vehicles))
    false_positives = len(flagged_vehicles - malicious_vehicles)
    true_negatives = len(set(data.get("active_vehicles", [])) - malicious_vehicles - flagged_vehicles)
    false_negatives = len(malicious_vehicles - flagged_vehicles)
    
    # Calculate metrics
    if true_positives + false_positives > 0:
        precision = true_positives / (true_positives + false_positives)
    else:
        precision = 0
    
    if true_positives + false_negatives > 0:
        recall = true_positives / (true_positives + false_negatives)
    else:
        recall = 0
    
    if precision + recall > 0:
        f1_score = 2 * precision * recall / (precision + recall)
    else:
        f1_score = 0
    
    return {
        "confusion_matrix": {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_negatives": false_negatives
        },
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score
        },
        "malicious_vehicles": list(malicious_vehicles),
        "flagged_vehicles": list(flagged_vehicles)
    }





def generate_visualizations(data, output_dir):
    """Generate all visualizations"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Get analysis results
    platoon_performance = analyze_platoon_performance(data)
    trust_evolution = analyze_trust_score_evolution(data)
    sol_usage = analyze_sol_usage(data)
    latency_analysis = analyze_latency_vs_load(data)
    
    # 1. Platoon Join Performance Visualizations
    if platoon_performance is not None and not platoon_performance.empty:
        # Success rate vs time
        plt.figure(figsize=(12, 6))
        plt.plot(platoon_performance["minute"], platoon_performance["success_rate"], 
                 'o-', color='blue', linewidth=2)
        plt.title("Platoon Join Success Rate Over Time", fontsize=14)
        plt.xlabel("Time")
        plt.ylabel("Success Rate (%)")
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        plt.gcf().autofmt_xdate()
        plt.tight_layout()
        plt.savefig(f"{output_dir}/platoon_success_rate.png", dpi=300)
        plt.close()
        
        # Success rate vs concurrency
        plt.figure(figsize=(10, 6))
        plt.scatter(platoon_performance["concurrent_joins"], platoon_performance["success_rate"], 
                   s=80, alpha=0.7)
        
        # Add best fit line
        if len(platoon_performance) > 1:
            z = np.polyfit(platoon_performance["concurrent_joins"], platoon_performance["success_rate"], 1)
            p = np.poly1d(z)
            x_range = np.linspace(min(platoon_performance["concurrent_joins"]), 
                                 max(platoon_performance["concurrent_joins"]), 100)
            plt.plot(x_range, p(x_range), "r--", linewidth=2)
        
        plt.title("Platoon Join Success Rate vs Concurrent Requests", fontsize=14)
        plt.xlabel("Concurrent Join Requests")
        plt.ylabel("Success Rate (%)")
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(f"{output_dir}/success_vs_concurrency.png", dpi=300)
        plt.close()
        
        # Latency vs concurrency
        plt.figure(figsize=(10, 6))
        plt.scatter(platoon_performance["concurrent_joins"], platoon_performance["mean"], 
                   s=80, alpha=0.7, color="green")
        
        # Add best fit line
        if len(platoon_performance) > 1:
            z = np.polyfit(platoon_performance["concurrent_joins"], platoon_performance["mean"], 1)
            p = np.poly1d(z)
            x_range = np.linspace(min(platoon_performance["concurrent_joins"]), 
                                 max(platoon_performance["concurrent_joins"]), 100)
            plt.plot(x_range, p(x_range), "r--", linewidth=2)
        
        plt.title("Join Latency vs Concurrent Requests", fontsize=14)
        plt.xlabel("Concurrent Join Requests")
        plt.ylabel("Average Latency (seconds)")
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(f"{output_dir}/latency_vs_concurrency.png", dpi=300)
        plt.close()
    
    # 2. Trust Score Evolution Visualizations
    if trust_evolution and "trust_by_minute" in trust_evolution and trust_evolution["trust_by_minute"] is not None:
        trust_by_minute = trust_evolution["trust_by_minute"]
        
        # Trust score evolution over time
        plt.figure(figsize=(12, 6))
        plt.plot(trust_by_minute["minute"], trust_by_minute["mean"], 
                'b-', linewidth=2, label='Mean Trust Score')
        
        # Add confidence interval
        plt.fill_between(trust_by_minute["minute"],
                         trust_by_minute["mean"] - trust_by_minute["std"],
                         trust_by_minute["mean"] + trust_by_minute["std"],
                         color='blue', alpha=0.2, label='±1 Std Dev')
        
        # Add min/max
        plt.plot(trust_by_minute["minute"], trust_by_minute["min"], 
                'r--', linewidth=1, label='Min Score')
        plt.plot(trust_by_minute["minute"], trust_by_minute["max"], 
                'g--', linewidth=1, label='Max Score')
        
        plt.title("Trust Score Evolution Over Time", fontsize=14)
        plt.xlabel("Time")
        plt.ylabel("Trust Score")
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        plt.gcf().autofmt_xdate()
        plt.tight_layout()
        plt.savefig(f"{output_dir}/trust_score_evolution.png", dpi=300)
        plt.close()
        
        # Compare normal vs malicious if available
        if "trust_by_type" in trust_evolution and trust_evolution["trust_by_type"] is not None:
            trust_by_type = trust_evolution["trust_by_type"]
            
            plt.figure(figsize=(12, 6))
            
            if "normal_trust" in trust_by_type.columns:
                plt.plot(trust_by_type["minute"], trust_by_type["normal_trust"], 
                        'g-', linewidth=2, label='Normal Vehicles')
                
            if "malicious_trust" in trust_by_type.columns:
                plt.plot(trust_by_type["minute"], trust_by_type["malicious_trust"], 
                        'r-', linewidth=2, label='Malicious Vehicles')
            
            # Add a horizontal line for typical threshold
            plt.axhline(y=75, color='black', linestyle='--', alpha=0.7, label='Typical Threshold')
            
            plt.title("Trust Score Comparison: Normal vs Malicious Vehicles", fontsize=14)
            plt.xlabel("Time")
            plt.ylabel("Average Trust Score")
            plt.legend()
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            plt.gcf().autofmt_xdate()
            plt.tight_layout()
            plt.savefig(f"{output_dir}/trust_score_comparison.png", dpi=300)
            plt.close()
    
    # 3. SOL Usage Visualizations
    if sol_usage and "cost_by_minute" in sol_usage and sol_usage["cost_by_minute"] is not None:
        # SOL usage over time
        cost_by_minute = sol_usage["cost_by_minute"]
        
        plt.figure(figsize=(12, 6))
        plt.plot(cost_by_minute["minute"], cost_by_minute["estimated_cost"], 
                'o-', color='green', linewidth=2)
        
        # Add cumulative line on secondary y-axis
        cost_by_minute["cumulative_cost"] = cost_by_minute["estimated_cost"].cumsum()
        
        ax2 = plt.twinx()
        ax2.plot(cost_by_minute["minute"], cost_by_minute["cumulative_cost"], 
                '--', color='blue', linewidth=2, label='Cumulative Cost')
        ax2.set_ylabel("Cumulative SOL Cost", color='blue')
        
        plt.title("SOL Usage Over Time", fontsize=14)
        plt.xlabel("Time")
        plt.ylabel("SOL Cost per Minute")
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        plt.gcf().autofmt_xdate()
        plt.tight_layout()
        plt.savefig(f"{output_dir}/sol_usage_time.png", dpi=300)
        plt.close()
        
        # SOL usage by transaction type
        if "cost_by_type" in sol_usage and sol_usage["cost_by_type"] is not None:
            cost_by_type = sol_usage["cost_by_type"]
            cost_by_type = cost_by_type.sort_values("estimated_cost", ascending=False)
            
            plt.figure(figsize=(10, 6))
            bars = plt.bar(cost_by_type["type"], cost_by_type["estimated_cost"], 
                          color='skyblue', edgecolor='navy')
            
            # Add values on top of bars
            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height + 0.000001,
                        f'{height:.6f}',
                        ha='center', va='bottom', rotation=0, fontsize=9)
            
            plt.title("SOL Usage by Transaction Type", fontsize=14)
            plt.xlabel("Transaction Type")
            plt.ylabel("Total SOL Cost")
            plt.grid(axis='y', linestyle='--', alpha=0.7)
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            plt.savefig(f"{output_dir}/sol_by_type.png", dpi=300)
            plt.close()
        
        # Cost per vehicle
        if "vehicle_costs" in sol_usage and sol_usage["vehicle_costs"]:
            vehicle_costs = sol_usage["vehicle_costs"]
            
            # Convert to DataFrame
            vehicle_cost_df = pd.DataFrame([
                {"vehicle_id": v_id, "cost": cost}
                for v_id, cost in vehicle_costs.items()
            ])
            
            # Sort by cost
            vehicle_cost_df = vehicle_cost_df.sort_values("cost", ascending=False)
            
            # Take top 15 vehicles
            if len(vehicle_cost_df) > 15:
                vehicle_cost_df = vehicle_cost_df.head(15)
            
            plt.figure(figsize=(12, 6))
            bars = plt.bar(vehicle_cost_df["vehicle_id"], vehicle_cost_df["cost"], 
                          color='lightgreen', edgecolor='darkgreen')
            
            # Add values on top of bars
            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height + 0.000001,
                        f'{height:.6f}',
                        ha='center', va='bottom', rotation=0, fontsize=9)
            
            plt.title("SOL Usage by Vehicle", fontsize=14)
            plt.xlabel("Vehicle ID")
            plt.ylabel("Total SOL Cost")
            plt.grid(axis='y', linestyle='--', alpha=0.7)
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            plt.savefig(f"{output_dir}/sol_by_vehicle.png", dpi=300)
            plt.close()
        
        # SOL usage by time and type
        if "cost_by_minute_type" in sol_usage and sol_usage["cost_by_minute_type"] is not None:
            cost_by_time_type = sol_usage["cost_by_minute_type"]
            
            # Only proceed if there are multiple transaction types
            if len(cost_by_time_type.columns) > 2:  # More than just 'minute' and one tx type
                plt.figure(figsize=(12, 6))
                
                # Plot each transaction type
                for column in cost_by_time_type.columns:
                    if column != "minute":
                        plt.plot(cost_by_time_type["minute"], cost_by_time_type[column], 
                                'o-', linewidth=2, label=column)
                
                plt.title("SOL Usage by Transaction Type Over Time", fontsize=14)
                plt.xlabel("Time")
                plt.ylabel("SOL Cost")
                plt.legend()
                plt.grid(True, linestyle='--', alpha=0.7)
                plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
                plt.gcf().autofmt_xdate()
                plt.tight_layout()
                plt.savefig(f"{output_dir}/sol_by_type_time.png", dpi=300)
                plt.close()
    
    # 4. Latency Analysis Visualizations
    if latency_analysis and "latency_vs_load" in latency_analysis and latency_analysis["latency_vs_load"] is not None:
        latency_vs_load = latency_analysis["latency_vs_load"]
        
        # Group by tx_type
        plt.figure(figsize=(12, 6))
        
        # Get unique transaction types
        tx_types = latency_vs_load["tx_type"].unique()
        
        # Plot each transaction type
        for tx_type in tx_types:
            type_data = latency_vs_load[latency_vs_load["tx_type"] == tx_type]
            plt.scatter(type_data["tx_count"], type_data["latency"], 
                       label=tx_type, alpha=0.7, s=50)
            
            # Add best fit line if enough points
            if len(type_data) > 2:
                z = np.polyfit(type_data["tx_count"], type_data["latency"], 1)
                p = np.poly1d(z)
                x_range = np.linspace(min(type_data["tx_count"]), max(type_data["tx_count"]), 100)
                plt.plot(x_range, p(x_range), "--", linewidth=1)
        
        plt.title("Transaction Latency vs System Load", fontsize=14)
        plt.xlabel("Transactions per Minute")
        plt.ylabel("Average Latency (seconds)")
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.legend()
        plt.tight_layout()
        plt.savefig(f"{output_dir}/latency_vs_load.png", dpi=300)
        plt.close()
        
        # Success rate vs load if available
        if "success_vs_load" in latency_analysis and latency_analysis["success_vs_load"] is not None:
            success_vs_load = latency_analysis["success_vs_load"]
            
            plt.figure(figsize=(12, 6))
            
            # Get unique transaction types
            tx_types = success_vs_load["tx_type"].unique()
            
            # Plot each transaction type
            for tx_type in tx_types:
                type_data = success_vs_load[success_vs_load["tx_type"] == tx_type]
                plt.scatter(type_data["tx_count"], type_data["success_rate"], 
                           label=tx_type, alpha=0.7, s=50)
                
                # Add best fit line if enough points
                if len(type_data) > 2:
                    z = np.polyfit(type_data["tx_count"], type_data["success_rate"], 1)
                    p = np.poly1d(z)
                    x_range = np.linspace(min(type_data["tx_count"]), max(type_data["tx_count"]), 100)
                    plt.plot(x_range, p(x_range), "--", linewidth=1)
            
            plt.title("Transaction Success Rate vs System Load", fontsize=14)
            plt.xlabel("Transactions per Minute")
            plt.ylabel("Success Rate (%)")
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.legend()
            plt.tight_layout()
            plt.savefig(f"{output_dir}/success_rate_vs_load.png", dpi=300)
            plt.close()
    
    print(f"✅ Generated visualizations in {output_dir}")

    # 5. Malicious Vehicle Detection Visualizations
    malicious_detection = analyze_malicious_detection(data)
    if malicious_detection and "confusion_matrix" in malicious_detection:
        confusion = malicious_detection["confusion_matrix"]
        metrics = malicious_detection["metrics"]
        
        # Create confusion matrix visualization
        plt.figure(figsize=(8, 6))
        
        confusion_matrix = [
            [confusion["true_negatives"], confusion["false_positives"]],
            [confusion["false_negatives"], confusion["true_positives"]]
        ]
        

        sns.heatmap(confusion_matrix, annot=True, fmt='d', cmap='Blues',
                    xticklabels=['Not Flagged', 'Flagged'],
                    yticklabels=['Normal', 'Malicious'])
        
        plt.title('Malicious Vehicle Detection Confusion Matrix', fontsize=14)
        plt.ylabel('Actual Vehicle Type', fontsize=12)
        plt.xlabel('Detection Result', fontsize=12)
        
        # Add metrics text box
        metrics_text = f"Precision: {metrics['precision']:.3f}\nRecall: {metrics['recall']:.3f}\nF1 Score: {metrics['f1_score']:.3f}"
        plt.annotate(metrics_text, xy=(0.02, 0.02), xycoords='figure fraction', 
                    fontsize=10, bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))
        
        plt.tight_layout()
        plt.savefig(f"{output_dir}/malicious_detection_matrix.png", dpi=300)
        plt.close()
        
        # Create trust score comparison for malicious vs normal vehicles
        if "malicious_vehicles" in malicious_detection and trust_evolution and "trust_by_minute" in trust_evolution:
            malicious_set = set(malicious_detection["malicious_vehicles"])
            
            if malicious_set and "trust_scores" in data:
                # Prepare trust score data
                trust_df = pd.DataFrame(data["trust_scores"])
                trust_df["timestamp"] = pd.to_datetime(trust_df["timestamp"])
                trust_df["minute"] = trust_df["timestamp"].dt.floor("1min")
                trust_df["is_malicious"] = trust_df["vehicle_id"].isin(malicious_set)
                
                # Calculate average trust by minute and type
                trust_by_type = trust_df.groupby(["minute", "is_malicious"])["trust_score"].mean().reset_index()
                
                # Create plot
                plt.figure(figsize=(12, 6))
                
                # Plot normal vehicles
                normal_data = trust_by_type[trust_by_type["is_malicious"] == False]
                if not normal_data.empty:
                    plt.plot(normal_data["minute"], normal_data["trust_score"], 
                            'g-', linewidth=2, label='Normal Vehicles')
                
                # Plot malicious vehicles
                malicious_data = trust_by_type[trust_by_type["is_malicious"] == True]
                if not malicious_data.empty:
                    plt.plot(malicious_data["minute"], malicious_data["trust_score"], 
                            'r-', linewidth=2, label='Malicious Vehicles')
                
                # Add standard threshold line
                plt.axhline(y=75, color='black', linestyle='--', alpha=0.7, label='Typical Threshold')
                
                plt.title("Trust Score: Normal vs Malicious Vehicles", fontsize=14)
                plt.xlabel("Time")
                plt.ylabel("Average Trust Score")
                plt.legend()
                plt.grid(True, linestyle='--', alpha=0.7)
                plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
                plt.gcf().autofmt_xdate()
                plt.tight_layout()
                plt.savefig(f"{output_dir}/malicious_trust_comparison.png", dpi=300)
                plt.close()



def generate_summary_report(data, output_dir):
    """Generate a summary report in text format"""
    if not data:
        return
    
    # Create timestamp for report
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Start report
    report = [
        "==================================",
        f"PERFORMANCE MONITORING REPORT",
        f"Generated: {timestamp}",
        "==================================\n"
    ]
    
    # Active vehicles
    active_vehicles = data.get("active_vehicles", [])
    report.append(f"Active Vehicles: {len(active_vehicles)}")
    if active_vehicles:
        report.append(f"Vehicle IDs: {', '.join(active_vehicles[:10])}" + 
                     (f" and {len(active_vehicles)-10} more..." if len(active_vehicles) > 10 else ""))
    
    # Trust score stats
    trust_scores = data.get("trust_scores", [])
    if trust_scores:
        scores = [s.get("trust_score", 0) for s in trust_scores]
        report.append(f"\nTrust Score Statistics:")
        report.append(f"- Total updates: {len(trust_scores)}")
        report.append(f"- Average score: {sum(scores)/len(scores):.2f}")
        report.append(f"- Min score: {min(scores):.2f}")
        report.append(f"- Max score: {max(scores):.2f}")
    
    # Platoon join stats
    join_attempts = data.get("join_attempts", [])
    if join_attempts:
        successful = sum(1 for j in join_attempts if j.get("success", False))
        success_rate = (successful / len(join_attempts)) * 100
        
        report.append(f"\nPlatoon Join Statistics:")
        report.append(f"- Total attempts: {len(join_attempts)}")
        report.append(f"- Successful joins: {successful}")
        report.append(f"- Success rate: {success_rate:.1f}%")
        
        # Calculate average latency
        latencies = [j.get("latency", 0) for j in join_attempts]
        if latencies:
            report.append(f"- Average join latency: {sum(latencies)/len(latencies):.3f}s")
    
    # SOL usage stats
    if "sol_usage" in data:
        total_sol = 0
        tx_count = 0
        
        for vehicle_id, usage in data["sol_usage"].items():
            total_sol += usage.get("total_cost", 0)
            tx_count += len(usage.get("transactions", []))
        
        report.append(f"\nSOL Usage Statistics:")
        report.append(f"- Total SOL used: {total_sol:.6f}")
        report.append(f"- Transactions recorded: {tx_count}")
        report.append(f"- Average cost per transaction: {(total_sol/tx_count):.6f} SOL" if tx_count > 0 else "N/A")
        report.append(f"- Average cost per vehicle: {(total_sol/len(data['sol_usage'])):.6f} SOL" if data['sol_usage'] else "N/A")
    
    # Transaction latency stats
    if "transaction_latency" in data:
        report.append(f"\nTransaction Latency Statistics:")
        
        for tx_type, records in data["transaction_latency"].items():
            if records:
                latencies = [r.get("latency", 0) for r in records]
                if latencies:
                    avg_latency = sum(latencies) / len(latencies)
                    min_latency = min(latencies)
                    max_latency = max(latencies)
                    
                    # Calculate success rate if available
                    if any("success" in r for r in records):
                        success_count = sum(1 for r in records if r.get("success", False))
                        success_rate = (success_count / len(records)) * 100
                        
                        report.append(f"- {tx_type.replace('_', ' ').title()}:")
                        report.append(f"  * Transactions: {len(records)}")
                        report.append(f"  * Success rate: {success_rate:.1f}%")
                        report.append(f"  * Avg latency: {avg_latency:.3f}s (min: {min_latency:.3f}s, max: {max_latency:.3f}s)")
                    else:
                        report.append(f"- {tx_type.replace('_', ' ').title()}:")
                        report.append(f"  * Transactions: {len(records)}")
                        report.append(f"  * Avg latency: {avg_latency:.3f}s (min: {min_latency:.3f}s, max: {max_latency:.3f}s)")
    
    # Add metrics if available
    if "metrics" in data:
        report.append(f"\nAdditional Metrics:")
        
        if "platoon" in data["metrics"]:
            platoon = data["metrics"]["platoon"]
            report.append(f"- Platoon Performance:")
            report.append(f"  * Join success rate: {platoon.get('join_success_rate', 0):.1f}%")
            report.append(f"  * Average join latency: {platoon.get('avg_join_latency', 0):.3f}s")
        
        if "sol" in data["metrics"]:
            sol = data["metrics"]["sol"]
            report.append(f"- SOL Consumption:")
            report.append(f"  * Total used: {sol.get('total_sol_used', 0):.6f}")
            report.append(f"  * Avg per vehicle: {sol.get('avg_sol_per_vehicle', 0):.6f}")
            
            if "sol_by_transaction_type" in sol:
                report.append(f"  * By transaction type:")
                for tx_type, cost in sol["sol_by_transaction_type"].items():
                    report.append(f"    - {tx_type}: {cost:.6f} SOL")


    # Add malicious detection stats to report
    malicious_detection = analyze_malicious_detection(data)
    if malicious_detection and "confusion_matrix" in malicious_detection:
        confusion = malicious_detection["confusion_matrix"]
        metrics = malicious_detection["metrics"]
        
        report.append(f"\nMalicious Vehicle Detection:")
        report.append(f"- True positives: {confusion['true_positives']}")
        report.append(f"- False positives: {confusion['false_positives']}")
        report.append(f"- True negatives: {confusion['true_negatives']}")
        report.append(f"- False negatives: {confusion['false_negatives']}")
        report.append(f"- Precision: {metrics['precision']:.3f}")
        report.append(f"- Recall: {metrics['recall']:.3f}")
        report.append(f"- F1 Score: {metrics['f1_score']:.3f}")
        
        if "malicious_vehicles" in malicious_detection:
            malicious_count = len(malicious_detection["malicious_vehicles"])
            report.append(f"- Identified malicious vehicles: {malicious_count}")
            
            if malicious_count > 0 and malicious_count <= 10:
                report.append(f"  * IDs: {', '.join(malicious_detection['malicious_vehicles'])}")
            elif malicious_count > 10:
                report.append(f"  * IDs (first 10): {', '.join(malicious_detection['malicious_vehicles'][:10])}...")

    # Write report to file
        report_file = f"{output_dir}/performance_summary.txt"
        with open(report_file, 'w') as f:
            f.write("\n".join(report))
        
        print(f"✅ Generated summary report: {report_file}")
    
    # Return report text
    return "\n".join(report)

def main():
    """Main monitoring loop"""
    print(f"Starting Advanced Performance Monitoring")
    print(f"- Monitoring interval: {MONITORING_INTERVAL} seconds")
    print(f"- Input file: {INPUT_FILE}")
    print(f"- Output directory: {OUTPUT_DIR}")
    
    # Ensure output directory exists
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"Created output directory: {OUTPUT_DIR}")
    
    while True:
        try:
            print(f"\n=== Running performance analysis at {datetime.now().isoformat()} ===")
            
            # Load latest data
            data = load_data()
            
            if data:
                # Generate visualizations
                generate_visualizations(data, OUTPUT_DIR)
                
                # Generate summary report
                report = generate_summary_report(data, OUTPUT_DIR)
                
                # Print summary
                print("\nPERFORMANCE SUMMARY:")
                if "active_vehicles" in data:
                    print(f"- Active vehicles: {len(data['active_vehicles'])}")
                if "trust_scores" in data:
                    print(f"- Trust score updates: {len(data['trust_scores'])}")
                if "join_attempts" in data:
                    successful = sum(1 for j in data["join_attempts"] if j.get("success", False))
                    print(f"- Platoon join success: {successful}/{len(data['join_attempts'])} ({(successful/len(data['join_attempts'])*100):.1f}%)")
                
                # Additional metrics if available
                if "metrics" in data and "sol" in data["metrics"]:
                    sol = data["metrics"]["sol"]
                    print(f"- Total SOL used: {sol.get('total_sol_used', 0):.6f}")
            else:
                print("❌ No data available to analyze")
            
            # Wait for next monitoring cycle
            print(f"\nWaiting {MONITORING_INTERVAL} seconds until next analysis...")
            time.sleep(MONITORING_INTERVAL)
            
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
            break
        except Exception as e:
            print(f"Error in monitoring cycle: {e}")
            # Sleep a bit longer after error
            time.sleep(max(10, MONITORING_INTERVAL))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Performance Monitoring")
    parser.add_argument("--interval", type=float, default=30.0, 
                        help="Monitoring interval in seconds (default: 30.0)")
    parser.add_argument("--input", type=str, default="trust_score_data.json",
                        help="Input data file")
    parser.add_argument("--output-dir", type=str, default="monitoring_results",
                        help="Output directory for reports and visualizations")
    
    args = parser.parse_args()
    
    MONITORING_INTERVAL = args.interval
    INPUT_FILE = args.input
    OUTPUT_DIR = args.output_dir
    
    main()