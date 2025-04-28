import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import axios from "axios";
import "./VehicleNodeView.css";

function PlatoonDashboard() {
  const { rsuId: rawRsuId } = useParams();
  const rsuId = rawRsuId.toLowerCase();
  const [rsuInfo, setRsuInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [airdropLoading, setAirdropLoading] = useState(false);
  const [thresholdInput, setThresholdInput] = useState("");
  const [statusMessage, setStatusMessage] = useState(null);
  const [memberDetails, setMemberDetails] = useState([]);

  const fetchRsuInfo = async () => {
    setLoading(true);
    try {
      console.log(`Fetching platoon info for RSU: ${rsuId}`);
      const res = await axios.get(`http://127.0.0.1:5002/platoon-info/${rsuId}`, {
        headers: { "Cache-Control": "no-cache" },
        params: { t: Date.now() }, // Cache-busting
      });
      console.log("Platoon info response:", res.data);
      setRsuInfo(res.data);
      if (res.data.threshold !== undefined) {
        setThresholdInput(res.data.threshold.toString());
      } else {
        setThresholdInput("70");
      }
      if (res.data.members) {
        setMemberDetails(res.data.members); // Use members directly
      } else {
        setMemberDetails([]);
      }
    } catch (err) {
      console.error("Error fetching RSU info:", err);
      setRsuInfo(null);
      setThresholdInput("70");
      setMemberDetails([]);
    } finally {
      setLoading(false);
    }
  };

  const requestAirdrop = async () => {
    setAirdropLoading(true);
    try {
      const res = await axios.post(`http://127.0.0.1:5002/rsu-airdrop/${rsuId}`);
      alert(res.data.message || "Airdrop complete.");
      await fetchRsuInfo();
    } catch (err) {
      alert("Airdrop failed: " + (err.response?.data?.error || err.message));
    } finally {
      setAirdropLoading(false);
    }
  };

  const updateThreshold = async () => {
    setStatusMessage(null);
    const threshold = parseInt(thresholdInput, 10);
    if (isNaN(threshold) || threshold < 0 || threshold > 255) {
      setStatusMessage("❌ Invalid threshold (0-255).");
      return;
    }
    try {
      console.log(`Updating threshold for RSU: ${rsuId} to ${threshold}`);
      const res = await axios.post(
        `http://127.0.0.1:5002/create-platoon-contract/${rsuId}/${threshold}`
      );
      console.log("Update threshold response:", res.data);
      setStatusMessage(`✅ Threshold ${res.data.status} to ${threshold}!`);
      await fetchRsuInfo();
    } catch (err) {
      console.error("Update Threshold Error:", err);
      setStatusMessage(
        `❌ Failed to update threshold: ${err.response?.data?.error || err.message}`
      );
    }
  };

  const removeMember = async (vehicleId) => {
    try {
      console.log(`Removing vehicle ${vehicleId} from RSU: ${rsuId}`);
      const res = await axios.post(
        `http://127.0.0.1:5002/remove-from-platoon/${vehicleId}/${rsuId}`
      );
      console.log("Remove vehicle response:", res.data);
      alert(`🚫 Vehicle ${vehicleId} removed from platoon.`);
      await fetchRsuInfo();
    } catch (err) {
      console.error("Remove vehicle error:", err);
      alert("❌ Failed to remove vehicle: " + (err.response?.data?.error || err.message));
    }
  };

  useEffect(() => {
    fetchRsuInfo();
  }, [rsuId]);

  if (loading) return <div style={{ padding: 20 }}>Loading RSU data...</div>;

  const walletInfo = (
    <>
      {rsuInfo?.wallet && (
        <p>
          <strong>Wallet:</strong> {rsuInfo.wallet}
        </p>
      )}
      {rsuInfo?.platoon_pda && (
        <p>
          <strong>PDA:</strong> {rsuInfo.platoon_pda}
        </p>
      )}
      {rsuInfo?.balance !== undefined && (
        <p>
          <strong>Balance:</strong> {rsuInfo.balance.toFixed(4)} SOL
        </p>
      )}
      {rsuInfo?.created_by && (
        <p>
          <strong>Creator:</strong> {rsuInfo.created_by}
        </p>
      )}
    </>
  );

  if (rsuInfo?.error?.includes("not initialized")) {
    return (
      <div style={{ padding: 20 }}>
        <h3>⚠️ RSU "{rsuId}" is not yet registered on-chain.</h3>
        {walletInfo}
        <label>
          Set Initial Threshold:
          <input
            type="number"
            value={thresholdInput}
            onChange={(e) => setThresholdInput(e.target.value)}
            className="border ml-2 p-1"
            min="0"
            max="255"
          />
        </label>
        <button
          onClick={updateThreshold}
          className="mt-4 bg-blue-600 text-white px-3 py-2 rounded"
        >
          🚀 Register RSU to Blockchain
        </button>
        {statusMessage && (
          <div className="mt-4 text-blue-600">{statusMessage}</div>
        )}
      </div>
    );
  }

  return (
    <div style={{ padding: "20px" }}>
      <h2>📡 RSU Dashboard ({rsuId})</h2>
      {walletInfo}
      {rsuInfo.threshold !== undefined ? (
        <p>
          <strong>Current Threshold:</strong> {rsuInfo.threshold}
        </p>
      ) : (
        <p>
          <strong>Current Threshold:</strong> Not set
        </p>
      )}

      <div style={{ marginTop: "20px" }}>
        <label>
          Set Trust Threshold:
          <input
            type="number"
            value={thresholdInput}
            onChange={(e) => setThresholdInput(e.target.value)}
            className="border ml-2 p-1"
            min="0"
            max="255"
            placeholder="Enter threshold (0-255)"
          />
        </label>
        <button
          onClick={updateThreshold}
          className="ml-4 bg-blue-700 text-white px-4 py-2 rounded"
        >
          💾 Save Threshold
        </button>
      </div>

      <button
        onClick={requestAirdrop}
        disabled={airdropLoading}
        className="mt-4 bg-green-500 text-white px-3 py-1 rounded"
      >
        {airdropLoading ? "Requesting Airdrop..." : "💸 Request Airdrop"}
      </button>

      {statusMessage && (
        <div className="mt-4 text-blue-600">{statusMessage}</div>
      )}

      {memberDetails.length > 0 && (
        <div className="mt-6">
          <h3 className="text-lg font-semibold mb-2">🚘 Vehicles in Platoon</h3>
          <ul className="list-disc ml-6">
            {memberDetails.map(({ vehicle_id, trust_score }, index) => (
              <li key={index} className="flex justify-between items-center">
                <span>
                  <strong>{vehicle_id}</strong>
                  <small className="text-gray-500">
                    {" "}
                    (Trust Score: {trust_score})
                  </small>
                </span>
                <button
                  onClick={() => removeMember(vehicle_id)}
                  className="bg-red-500 text-white px-2 py-1 rounded ml-4"
                >
                  ❌ Remove
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default PlatoonDashboard;