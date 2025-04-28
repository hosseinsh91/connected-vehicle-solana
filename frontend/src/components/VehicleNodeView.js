import React, { useEffect, useState } from "react";
import axios from "axios";
import { useParams } from "react-router-dom";
import "./VehicleNodeView.css";

function VehicleNodeView() {
  const { vehicleId } = useParams();
  const [vehicleInfo, setVehicleInfo] = useState(null);
  const [liveTrustScore, setLiveTrustScore] = useState(null);
  const [selectedRSU, setSelectedRSU] = useState(null);
  const [loading, setLoading] = useState(true);
  const [airdropLoading, setAirdropLoading] = useState(false);
  const [joinLoading, setJoinLoading] = useState(false);
  const [submitLoading, setSubmitLoading] = useState(false);
  const [resetLoading, setResetLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchVehicleInfo = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`http://127.0.0.1:5002/vehicle-info/${vehicleId}`);
      setVehicleInfo(res.data);
      setSelectedRSU(res.data.eligible_rsus?.[0]?.rsu_id || null);
      setError(null);
    } catch (err) {
      setError("Failed to fetch vehicle info.");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const fetchLiveTrustScore = async () => {
    try {
      const res = await axios.get(`http://127.0.0.1:5002/realtime-vehicle-data`);
      const score = res.data?.vehicles?.[vehicleId]?.trust_score;
      if (typeof score === "number") {
        setLiveTrustScore(score.toFixed(2));
      }
    } catch (err) {
      console.warn("⚠️ Could not fetch live trust score:", err);
    }
  };

  const requestAirdrop = async () => {
    setAirdropLoading(true);
    setError(null);
    try {
      const res = await axios.post(`http://127.0.0.1:5002/airdrop/${vehicleId}`);
      if (res.data.error) {
        setError("Airdrop failed: " + res.data.error);
      } else {
        alert("✅ Airdrop successful: " + res.data.result);
        fetchVehicleInfo();
      }
    } catch (err) {
      setError("❌ Airdrop error: " + (err.response?.data?.details || err.message));
    } finally {
      setAirdropLoading(false);
    }
  };

  const requestJoinPDA = async () => {
    setJoinLoading(true);
    setError(null);
    try {
      const res = await axios.post(`http://127.0.0.1:5002/join-pda/${vehicleId}`);
      if (res.data.status === "joined") {
        alert("🚀 PDA join successful!");
        fetchVehicleInfo();
      } else {
        setError("Join PDA failed: " + res.data.reason);
      }
    } catch (err) {
      setError("❌ Join PDA error: " + (err.response?.data?.error || err.message));
    } finally {
      setJoinLoading(false);
    }
  };

  const requestJoinPlatoon = async () => {
    if (!selectedRSU) return alert("❌ Please select an RSU.");
    try {
      const res = await axios.post(`http://127.0.0.1:5002/platoon-request/${vehicleId}/${selectedRSU}`);
      alert(`✅ Join request sent to ${selectedRSU}!`);
      fetchVehicleInfo();
    } catch (err) {
      alert("❌ Platoon join failed: " + (err.response?.data?.error || err.message));
    }
  };

  const submitTrustScore = async () => {
    setSubmitLoading(true);
    try {
      const res = await axios.post(`http://127.0.0.1:5002/update-trust/${vehicleId}`);
      alert("📤 Trust score submitted to PDA!");
      fetchVehicleInfo();
    } catch (err) {
      alert("❌ Failed to submit trust score: " + (err.response?.data?.error || err.message));
    } finally {
      setSubmitLoading(false);
    }
  };

  const resetVehicle = async () => {
    setResetLoading(true);
    try {
      const res = await axios.post(`http://127.0.0.1:5002/reset-vehicle/${vehicleId}`);
      alert(res.data.status || `Vehicle ${vehicleId} has been reset.`);
      fetchVehicleInfo();
    } catch (err) {
      console.error("Reset vehicle error:", err);
      alert("❌ Failed to reset vehicle.");
    } finally {
      setResetLoading(false);
    }
  };

  const removeFromPlatoon = async () => {
    if (!vehicleInfo || vehicleInfo.platoon_status === "not_joined") {
      alert("❌ Vehicle is not currently in a platoon.");
      return;
    }
    const rsuId = vehicleInfo.platoon_status.replace("joined_", "");
    try {
      const res = await axios.post(`http://127.0.0.1:5002/remove-from-platoon/${vehicleId}/${rsuId}`);
      alert(res.data.status || `Vehicle ${vehicleId} removed from ${rsuId}`);
      fetchVehicleInfo();
    } catch (err) {
      console.error("Remove error:", err);
      alert("❌ Failed to remove from platoon: " + (err.response?.data?.error || err.message));
    }
  };

  useEffect(() => {
    fetchVehicleInfo();
    fetchLiveTrustScore();
    const interval = setInterval(fetchLiveTrustScore, 2000);
    return () => clearInterval(interval);
  }, [vehicleId]);

  if (loading) {
    return (
      <div style={{ padding: "20px", textAlign: "center" }}>
        <div className="spinner"></div>
        <p>Loading vehicle data...</p>
      </div>
    );
  }

  if (!vehicleInfo) {
    return <div>⚠️ Vehicle not found.</div>;
  }

  const isEligible = (rsuId) =>
    vehicleInfo.eligible_rsus?.some((r) => r.rsu_id === rsuId);

  return (
    <div style={{ padding: "20px" }}>
      <h2>🚗 Vehicle Node Details</h2>
      <p><strong>Vehicle ID:</strong> {vehicleInfo.vehicle_id}</p>
      <p><strong>Public Key:</strong> {vehicleInfo.public_key}</p>
      <p><strong>Balance:</strong> {vehicleInfo.balance?.toFixed(4)} SOL</p>
      <p><strong>Joined PDA:</strong> {vehicleInfo.pda_joined ? "✅ Yes" : "❌ No"}</p>

      {vehicleInfo.pda_joined && (
        <>
          <p><strong>On-Chain Trust Score:</strong> {vehicleInfo.trust_score}</p>
          <p><strong>Live Calculated Trust Score:</strong> {liveTrustScore ?? "Loading..."}</p>
          <p><strong>Platoon Status:</strong> {vehicleInfo.platoon_status !== "not_joined"
            ? <>✅ Joined <strong>{vehicleInfo.platoon_status}</strong></>
            : "❌ Not Joined"}
          </p>

          {vehicleInfo.platoon_status !== "not_joined" && (
            <button
              onClick={removeFromPlatoon}
              style={{
                marginTop: "10px",
                backgroundColor: "#dc3545",
                color: "white",
                padding: "8px 12px",
                borderRadius: "5px",
                border: "none"
              }}
            >
              🗑 Remove from Platoon
            </button>
          )}

          <p><strong>Reward Tokens:</strong> {vehicleInfo.reward_tokens}</p>
          <p><strong>Malicious:</strong> {vehicleInfo.malicious_flag ? "🚨 Yes" : "✅ No"}</p>
          <p><strong>Can Join Platoon:</strong> {vehicleInfo.access_flags?.can_join_platoon ? "✅ Yes" : "❌ No"}</p>
          <p><strong>Can Share Data:</strong> {vehicleInfo.access_flags?.can_share_data ? "✅ Yes" : "❌ No"}</p>

          <p><strong>Join History:</strong> {vehicleInfo.join_history?.length > 0
            ? vehicleInfo.join_history.map((rsu, idx) => (
              <span key={idx} style={{ marginRight: "8px" }}>
                🛡️ {rsu}
              </span>
            ))
            : "None"}
          </p>

          {vehicleInfo.eligible_rsus?.length > 0 && (
            <div>
              <h4>🚦 Eligible RSUs</h4>
              <ul>
                {vehicleInfo.eligible_rsus.map(rsu => (
                  <li key={rsu.rsu_id}>
                    ✅ <strong>{rsu.rsu_id}</strong> (Threshold: {rsu.threshold})
                  </li>
                ))}
              </ul>

              <label>
                <strong>Select RSU to Join:</strong>{" "}
                <select
                  value={selectedRSU}
                  onChange={(e) => setSelectedRSU(e.target.value)}
                  style={{ marginLeft: "10px" }}
                >
                  {vehicleInfo.eligible_rsus.map(rsu => (
                    <option key={rsu.rsu_id} value={rsu.rsu_id}>
                      {rsu.rsu_id}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          )}

          {vehicleInfo.eligible_rsus?.length === 0 && (
            <p style={{ color: "orange", marginTop: "10px" }}>
              ⚠️ No eligible platoons: Trust score too low.
            </p>
          )}
        </>
      )}

      {error && <p style={{ color: "red" }}>❌ {error}</p>}

      <div style={{ marginTop: "20px" }}>
        <button onClick={requestAirdrop} disabled={airdropLoading} style={{ marginRight: "10px" }}>
          {airdropLoading ? "Requesting..." : "💸 Request Airdrop"}
        </button>

        <button onClick={requestJoinPDA} disabled={joinLoading || vehicleInfo.pda_joined}>
          {joinLoading ? "Joining PDA..." : vehicleInfo.pda_joined ? "✅ Already Joined" : "🔐 Join PDA"}
        </button>

        {vehicleInfo.pda_joined && (
          <>
            <button
              onClick={submitTrustScore}
              disabled={submitLoading}
              style={{
                marginTop: "10px",
                backgroundColor: "#28a745",
                color: "white",
                padding: "8px 12px",
                borderRadius: "5px",
                border: "none",
                marginLeft: "10px"
              }}
            >
              {submitLoading ? "Submitting..." : "📤 Submit Trust Score"}
            </button>

            {vehicleInfo.can_request_join && selectedRSU && (
              <button
                onClick={requestJoinPlatoon}
                style={{
                  marginTop: "10px",
                  backgroundColor: "#0077cc",
                  color: "white",
                  padding: "8px 12px",
                  borderRadius: "5px",
                  border: "none",
                  marginLeft: "10px"
                }}
              >
                🤝 Request Join Platoon
              </button>
            )}

            <button
              onClick={resetVehicle}
              disabled={resetLoading}
              style={{
                marginTop: "10px",
                backgroundColor: "#f0ad4e",
                color: "white",
                padding: "8px 12px",
                borderRadius: "5px",
                border: "none",
                marginLeft: "10px"
              }}
            >
              {resetLoading ? "Resetting..." : "🔄 Reset Vehicle"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

export default VehicleNodeView;