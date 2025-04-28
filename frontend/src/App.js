import React, { useEffect, useState, useRef } from "react";
import axios from "axios";
import { BrowserRouter as Router, Route, Routes, Link } from "react-router-dom";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import "./styles.css";
import carIconImg from "./car-icon.png";
import VehicleTracking from "./components/VehicleTracking";
import VehicleNodeView from "./components/VehicleNodeView";
import PlatoonDashboard from "./components/PlatoonDashboard";

// Define car icon for Leaflet (centered anchor)
const carIcon = new L.Icon({
  iconUrl: carIconImg,
  iconSize: [20, 20],
  iconAnchor: [10, 10],
  popupAnchor: [0, -10],
});

function VehicleMap() {
  const [vehicles, setVehicles] = useState({});
  const [rsus, setRsus] = useState({});
  const [platoons, setPlatoons] = useState({});
  const [error, setError] = useState(null);
  const [animatedVehicles, setAnimatedVehicles] = useState({});
  const lastUpdateRef = useRef({ vehicles: {}, timestamp: 0 });
  const animationFrameRef = useRef(null);

  const mapCenter = [50.720128, -1.880847];
  const UPDATE_INTERVAL = 1000;
  const ANIMATION_SPEED = 60;

  const lerp = (start, end, t) => start + (end - start) * t;

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get("http://127.0.0.1:5002/realtime-vehicle-data");
        const timestamp = Date.now();
        setVehicles(response.data.vehicles || {});
        setRsus(response.data.rsus || {});
        setPlatoons(response.data.platoons || {});
        setError(null);

        lastUpdateRef.current = {
          vehicles: animatedVehicles,
          timestamp: timestamp - UPDATE_INTERVAL,
        };
        setAnimatedVehicles(response.data.vehicles || {});
      } catch (err) {
        console.error("Error fetching vehicle data:", err);
        setError("Failed to load vehicle data. Is the backend running?");
      }
    };

    fetchData();
    const interval = setInterval(fetchData, UPDATE_INTERVAL);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const animate = () => {
      const now = Date.now();
      const elapsed = now - lastUpdateRef.current.timestamp;
      const t = Math.min(elapsed / UPDATE_INTERVAL, 1);

      const newAnimatedVehicles = {};
      Object.entries(vehicles).forEach(([vehicleID, currentData]) => {
        const lastData = lastUpdateRef.current.vehicles[vehicleID] || currentData;
        newAnimatedVehicles[vehicleID] = {
          ...currentData,
          Lat: lerp(lastData.Lat || currentData.Lat, currentData.Lat, t),
          Lon: lerp(lastData.Lon || currentData.Lon, currentData.Lon, t),
          Speed: currentData.Speed,
          "Trust Score": currentData["Trust Score"],
          Behavior: currentData.Behavior,
        };
      });

      setAnimatedVehicles(newAnimatedVehicles);
      animationFrameRef.current = requestAnimationFrame(animate);
    };

    animationFrameRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationFrameRef.current);
  }, [vehicles]);

  return (
    <div className="container">
      <h1>Real-Time Vehicle Tracking</h1>

      {error && <div className="error">{error}</div>}

      <div className="map-container">
        <MapContainer center={mapCenter} zoom={16} style={{ height: "800px", width: "1200px" }}>
          <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
          {Object.entries(animatedVehicles).map(([vehicleID, data]) => {
          if (
            !data ||
            typeof data.Lat !== "number" ||
            typeof data.Lon !== "number" ||
            isNaN(data.Lat) ||
            isNaN(data.Lon)
          ) {
            return null; // ⛔ Skip invalid vehicle
          }

          return (
            <Marker
              key={vehicleID}
              position={[data.Lat, data.Lon]}
              icon={carIcon}
            >
              <Popup>
                <b>Vehicle ID:</b> {vehicleID} <br />
                <b>Speed:</b> {(typeof data.Speed === "number" ? data.Speed.toFixed(2) : "0.00")} m/s <br />
                <b>Trust Score:</b> {(typeof data["Trust Score"] === "number" ? data["Trust Score"].toFixed(2) : "0.00")} <br />
                <b>Behavior:</b> {data.Behavior ?? "Unknown"}
              </Popup>
            </Marker>
          );
        })}

          {Object.entries(rsus).map(([rsuID, { lat, lon }]) => (
            <Marker key={rsuID} position={[lat, lon]}>
              <Popup>
                <b>RSU ID:</b> {rsuID}
              </Popup>
            </Marker>
          ))}
        </MapContainer>
      </div>
    </div>
  );
}

<div className="bg-blue-500 text-white p-4 rounded-xl">
  🚀 Tailwind is working!
</div>


function App() {
  return (
    <Router>
      <div className="app-container">
        <h1>Vehicle Tracking System</h1>
        <nav>
          <ul>
            <li><Link to="/">Vehicle Tracking</Link></li>
          </ul>
        </nav>
        <Routes>
          <Route path="/" element={<VehicleTracking />} />
          <Route path="/vehicle-node/:vehicleId" element={<VehicleNodeView />} />
          <Route path="/platoon/:rsuId" element={<PlatoonDashboard />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;