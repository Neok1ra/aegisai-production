import React from 'react';

interface Threat {
  hash: string;
  type: string;
  confidence: number;
  source_ip?: string;
  dest_ip?: string;
  timestamp: number;
  node_id?: string;
}

interface ThreatFeedProps {
  threats: Threat[];
}

export const ThreatFeed: React.FC<ThreatFeedProps> = ({ threats }) => {
  return (
    <div className="space-y-2">
      <h2 className="text-lg font-bold mb-2">Recent Threats</h2>
      {threats.length === 0 ? (
        <p className="text-gray-500">No threats detected yet</p>
      ) : (
        threats.map((threat) => (
          <div key={threat.hash} className="p-3 border rounded bg-gray-800">
            <div className="flex justify-between">
              <span className="font-mono text-sm">{threat.hash.substring(0, 8)}...</span>
              <span className="text-xs bg-red-500 px-2 py-1 rounded">
                {threat.confidence}%
              </span>
            </div>
            <div className="mt-1 text-sm">
              <span className="font-semibold">{threat.type}</span>
            </div>
            <div className="text-xs text-gray-400 mt-1">
              {new Date(threat.timestamp * 1000).toLocaleString()}
            </div>
          </div>
        ))
      )}
    </div>
  );
};