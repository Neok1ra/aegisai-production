'use client';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import { useEffect, useState } from 'react';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';

// Fix Leaflet icon issue
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

// Threat interface
interface Threat {
  hash: string;
  type: string;
  confidence: number;
  source_ip?: string;
  dest_ip?: string;
  timestamp: number;
  node_id: string;
}

export default function Dashboard() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [geoCache, setGeoCache] = useState<{[ip: string]: [number, number]}>({});

  const IPGEO_KEY = "4c860ff124be4f4793f317794178d222";

  // Get geolocation for an IP address
  const getGeo = async (ip?: string): Promise<[number, number]> => {
    if (!ip || ip.startsWith('192.168') || ip.startsWith('10.')) {
      return [51.5, -0.09];
    }
    
    if (geoCache[ip]) {
      return geoCache[ip];
    }
    
    try {
      const res = await fetch(`https://api.ipgeolocation.io/ipgeo?apiKey=${IPGEO_KEY}&ip=${ip}`);
      const data = await res.json();
      if (data.latitude && data.longitude) {
        const coords: [number, number] = [parseFloat(data.latitude), parseFloat(data.longitude)];
        setGeoCache(prev => ({ ...prev, [ip]: coords }));
        return coords;
      }
    } catch (error) {
      console.error('Geolocation error:', error);
    }
    
    // Return random coordinates if geolocation fails
    return [
      51.5 + (Math.random() - 0.5) * 20,
      -0.09 + (Math.random() - 0.5) * 40
    ];
  };

  // WebSocket connection effect
  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8000/ws');
    
    ws.onmessage = async (e) => {
      try {
        const t: Threat = JSON.parse(e.data);
        
        // Get geolocation for the source IP if not already cached
        if (t.source_ip && !geoCache[t.source_ip]) {
          await getGeo(t.source_ip);
        }
        
        setThreats(prev => [...prev.slice(-50), t]);
      } catch (error) {
        console.error('Error processing threat:', error);
      }
    };
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
    
    return () => {
      ws.close();
    };
  }, []);

  return (
    <div className="h-screen flex flex-col bg-black text-green-400 font-mono">
      <header className="p-4 border-b border-green-400">
        <h1 className="text-2xl">AegisAI — Global Threat Network</h1>
      </header>
      <div className="flex flex-1">
        <div className="w-3/4 h-full">
          {/* @ts-ignore */}
          <MapContainer center={[20, 0]} zoom={2} className="h-full">
            <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
            {threats.map(t => {
              const position: [number, number] = t.source_ip && geoCache[t.source_ip] 
                ? geoCache[t.source_ip] 
                : [20, 0];
                
              return (
                <Marker key={t.hash} position={position}>
                  <Popup>
                    <div className="text-xs">
                      <p><strong>{t.type}</strong></p>
                      <p>Confidence: {t.confidence}%</p>
                      <p>IP: {t.source_ip}</p>
                      <p>Time: {new Date(t.timestamp * 1000).toLocaleTimeString()}</p>
                    </div>
                  </Popup>
                </Marker>
              );
            })}
          </MapContainer>
        </div>
        <div className="w-1/4 p-4 overflow-y-auto border-l border-green-400">
          <h2 className="mb-2">Live Feed</h2>
          {threats.map(t => (
            <div key={t.hash} className="mb-2 p-2 bg-green-900 bg-opacity-20 rounded text-xs">
              <p>[{new Date(t.timestamp * 1000).toLocaleTimeString()}]</p>
              <p><strong>{t.type}</strong> {t.source_ip} → {t.dest_ip}</p>
              <p>Confidence: {t.confidence}%</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}