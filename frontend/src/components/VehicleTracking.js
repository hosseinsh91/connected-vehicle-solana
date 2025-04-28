import React, { useEffect, useState, useCallback } from "react";
import axios from "axios";
import { MapContainer, TileLayer, Marker, Popup, useMap } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import carIconImg from "../car-icon.png";
import rsuIconImg from "../rsu-icon.png";

// === ICONS ===
const carIcon = new L.Icon({
  iconUrl: carIconImg,
  iconSize: [20, 20],
  iconAnchor: [10, 10],
  popupAnchor: [0, -10],
});

const rsuIcon = new L.Icon({
  iconUrl: rsuIconImg,
  iconSize: [30, 30],
  iconAnchor: [15, 15],
  popupAnchor: [0, -10],
});

// === SMOOTHER MOVEMENT ===
const SmootherMovement = ({ vehicles, setVehiclePositions }) => {
  const map = useMap();

  useEffect(() => {
    const interval = setInterval(() => {
      setVehiclePositions((prevPositions) => {
        const newPositions = {};
        const now = Date.now();
        
        Object.entries(vehicles).forEach(([vehID, data]) => {
          if (!data || typeof data.lat !== "number" || typeof data.lon !== "number") return;

          const prev = prevPositions[vehID] || {
            Lat: data.lat,
            Lon: data.lon,
            Speed: data.speed ?? 0,
            TrustScore: data.trust_score ?? 0,
            Behavior: data.behavior ?? "Unknown",
            lastUpdate: now,
            vectorLat: 0,
            vectorLon: 0
          };

          // Calculate time-based factor for smoother transitions
          const timeDelta = (now - (prev.lastUpdate || now)) / 1000; // in seconds
          
          // Calculate vector from position change
          const vectorLat = data.lat - prev.Lat;
          const vectorLon = data.lon - prev.Lon;
          
          // Smooth the vectors with exponential moving average
          const smoothVectorLat = vectorLat * 0.3 + (prev.vectorLat || 0) * 0.7;
          const smoothVectorLon = vectorLon * 0.3 + (prev.vectorLon || 0) * 0.7;
          
          // Adaptive speed factor based on vehicle speed
          const speedFactor = Math.min((data.speed ?? 0) / 20.0, 1) * 0.5 + 0.1;
          
          newPositions[vehID] = {
            Lat: prev.Lat + vectorLat * speedFactor + (prev.vectorLat || 0) * (0.3),
            Lon: prev.Lon + vectorLon * speedFactor + (prev.vectorLon || 0) * (0.3),
            Speed: data.speed ?? prev.Speed,
            TrustScore: data.trust_score ?? prev.TrustScore,
            Behavior: data.behavior ?? prev.Behavior,
            lastUpdate: now,
            vectorLat: smoothVectorLat,
            vectorLon: smoothVectorLon
          };
        });
        
        return newPositions;
      });
    }, 33); // Update at ~30fps for smooth animation

    return () => clearInterval(interval);
  }, [vehicles]);

  return null;
};

// === MAIN COMPONENT ===
function VehicleTracking() {
  const [vehicles, setVehicles] = useState({});
  const [vehiclePositions, setVehiclePositions] = useState({});
  const [rsus, setRsus] = useState({});
  const [lastFetchTime, setLastFetchTime] = useState(0);
  const [fetchError, setFetchError] = useState(null);

  // === FETCH VEHICLE DATA ===
  const fetchVehicleData = useCallback(() => {
    const now = Date.now();
    // Add rate limiting to prevent overwhelming the server
    if (now - lastFetchTime < 800) return; // Limit to max ~1.25 requests per second
    
    setLastFetchTime(now);
    
    axios.get(`http://127.0.0.1:5002/realtime-vehicle-data?t=${now}`) // Add timestamp to prevent caching
      .then((response) => {
        setFetchError(null);
        const raw = response.data.vehicles;
        setVehicles(raw);
        setRsus(response.data.rsus);

        // Initialize positions on first load
        setVehiclePositions((prev) => {
          if (Object.keys(prev).length === 0) {
            const initial = {};
            Object.entries(raw).forEach(([vehID, data]) => {
              if (!data || typeof data.lat !== "number" || typeof data.lon !== "number") return;
              initial[vehID] = {
                Lat: data.lat,
                Lon: data.lon,
                Speed: data.speed ?? 0,
                TrustScore: data.trust_score ?? 0,
                Behavior: data.behavior ?? "Unknown",
                lastUpdate: now,
                vectorLat: 0,
                vectorLon: 0
              };
            });
            return initial;
          }
          return prev;
        });
      })
      .catch((error) => {
        console.error("Error fetching vehicle data:", error);
        setFetchError(error.message);
      });
  }, [lastFetchTime]);

  // === USE EFFECTS ===
  useEffect(() => {
    fetchVehicleData(); // Initial fetch
    
    // Regular data fetching
    const fetchInterval = setInterval(fetchVehicleData, 800);
    
    return () => clearInterval(fetchInterval);
  }, [fetchVehicleData]);

  return (
    <div className="container">
      <h1 className="text-xl font-bold mb-4">Real-Time Vehicle Tracking</h1>

      {fetchError && (
        <div className="bg-red-500 text-white p-4 rounded-xl mb-4">
          Error: {fetchError}. Retrying...
        </div>
      )}
      
      <div className="bg-blue-500 text-white p-4 rounded-xl mb-4">
        🚀 Tailwind is working!
      </div>

      {/* === Vehicle Selector === */}
      <div className="my-4">
        <label htmlFor="vehicleSelect" className="mr-2 font-bold">Select Vehicle:</label>
        <select
          id="vehicleSelect"
          className="p-2 border rounded"
          onChange={(e) => {
            const selected = e.target.value;
            if (selected) {
              window.location.href = `/vehicle-node/${selected}`;
            }
          }}
        >
          <option value="">-- Choose a Vehicle --</option>
          {Object.keys(vehicles).map((vehID) => (
            <option key={vehID} value={vehID}>{vehID}</option>
          ))}
        </select>
      </div>

      {/* === MAP === */}
      <div className="map-container">
        <MapContainer
          center={[50.720128, -1.880847]}
          zoom={16}
          style={{ height: "800px", width: "1200px" }}
        >
          <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
          <SmootherMovement vehicles={vehicles} setVehiclePositions={setVehiclePositions} />

          {/* RSU Markers */}
          {Object.entries(rsus).map(([rsuID, rsuData]) => {
            if (!rsuData || typeof rsuData.lat !== "number" || typeof rsuData.lon !== "number") return null;
            return (
              <Marker key={rsuID} position={[rsuData.lat, rsuData.lon]} icon={rsuIcon}>
                <Popup>
                  <b>RSU ID:</b> {rsuID}<br />
                  Lat: {rsuData.lat.toFixed(6)}<br />
                  Lon: {rsuData.lon.toFixed(6)}<br />
                  <button
                    className="text-blue-500 underline"
                    onClick={() => window.location.href = `/platoon/${rsuID}`}
                  >
                    Manage Platoon
                  </button>
                </Popup>
              </Marker>
            );
          })}

          {/* Vehicle Markers */}
          {Object.entries(vehiclePositions).map(([vehID, data]) => {
            const lat = data?.Lat;
            const lon = data?.Lon;
            if (typeof lat !== "number" || typeof lon !== "number" || isNaN(lat) || isNaN(lon)) return null;

            return (
              <Marker key={vehID} position={[lat, lon]} icon={carIcon}>
                <Popup>
                  <b>Vehicle ID:</b> {vehID}<br />
                  <b>Speed:</b> {data?.Speed?.toFixed(2) || "0.00"} m/s<br />
                  <b>Trust Score:</b> {data?.TrustScore?.toFixed(2) || "0.00"}<br />
                  <b>Behavior:</b> {data?.Behavior || "Unknown"}<br />
                  <button 
                    className="bg-blue-500 text-white px-2 py-1 rounded mt-1"
                    onClick={() => window.location.href = `/vehicle-node/${vehID}`}
                  >
                    View Full Node
                  </button>
                </Popup>
              </Marker>
            );
          })}
        </MapContainer>
      </div>
    </div>
  );
}

export default VehicleTracking;