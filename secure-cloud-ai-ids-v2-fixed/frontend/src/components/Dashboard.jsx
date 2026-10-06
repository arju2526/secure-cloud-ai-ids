import React, { useState, useEffect } from 'react';

export default function Dashboard({ token, user, onLogout }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);

  const fetchAlerts = async () => {
    try {
      const res = await fetch('/api/v1/detection/alerts', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setAlerts(data);
      }
    } catch (err) {
      console.error("Failed to fetch alerts", err);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 2000);
    return () => clearInterval(interval);
  }, [token]);

  // Export alerts as JSON
  const exportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(alerts, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `ids_threat_report_${new Date().toISOString()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Export alerts as CSV
  const exportCSV = () => {
    if (alerts.length === 0) return;
    const headers = ["ID", "Severity", "Alert Type", "Source IP", "Dest IP", "Dest Port", "Protocol", "Summary", "Timestamp"];
    const rows = alerts.map(a => [
      a.id,
      a.severity,
      a.alert_type,
      a.src_ip,
      a.dst_ip,
      a.dst_port,
      a.protocol,
      `"${a.summary || ''}"`,
      a.created_at
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `ids_threat_report_${new Date().toISOString()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  return (
    <div className="p-6 bg-slate-900 min-h-screen text-slate-100 font-sans">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">SOC Security Operations Center</h1>
          <p className="text-slate-400 text-sm">Real-time Hybrid AI Threat Detection Feed</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-400">{user?.username} · {user?.role}</span>
          <button onClick={onLogout} className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded text-sm font-semibold transition">Logout</button>
          <button
            onClick={exportCSV}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 rounded text-sm font-semibold transition"
          >
            Export CSV
          </button>
          <button
            onClick={exportJSON}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-sm font-semibold transition"
          >
            Export JSON
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-slate-800 p-4 rounded border border-slate-700">
          <span className="text-xs text-slate-400 font-semibold uppercase">Total Recorded Threats</span>
          <p className="text-3xl font-extrabold text-red-400 mt-1">{alerts.length}</p>
        </div>
        <div className="bg-slate-800 p-4 rounded border border-slate-700">
          <span className="text-xs text-slate-400 font-semibold uppercase">Engine Status</span>
          <p className="text-3xl font-extrabold text-emerald-400 mt-1">ONLINE</p>
        </div>
        <div className="bg-slate-800 p-4 rounded border border-slate-700">
          <span className="text-xs text-slate-400 font-semibold uppercase">Detection Engine</span>
          <p className="text-xl font-bold text-blue-400 mt-2">Isolation Forest + Rules</p>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="bg-slate-800 rounded border border-slate-700 overflow-hidden">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-slate-700 text-slate-200 uppercase text-xs">
            <tr>
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Alert Type</th>
              <th className="px-4 py-3">Source IP</th>
              <th className="px-4 py-3">Target IP</th>
              <th className="px-4 py-3">Summary</th>
              <th className="px-4 py-3">Timestamp</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700">
            {alerts.map((alert) => (
              <tr key={alert.id} className="hover:bg-slate-750 transition">
                <td className="px-4 py-3 font-mono text-xs">{alert.id}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-1 rounded text-xs font-bold ${
                    alert.severity === 'CRITICAL' ? 'bg-red-900 text-red-200 border border-red-700' :
                    alert.severity === 'HIGH' ? 'bg-orange-900 text-orange-200 border border-orange-700' :
                    'bg-slate-700 text-slate-300'
                  }`}>
                    {alert.severity}
                  </span>
                </td>
                <td className="px-4 py-3 font-medium text-slate-100">{alert.alert_type}</td>
                <td className="px-4 py-3 font-mono text-xs text-slate-400">{alert.src_ip}</td>
                <td className="px-4 py-3 font-mono text-xs text-slate-400">{alert.dst_ip}:{alert.dst_port}</td>
                <td className="px-4 py-3 text-xs">{alert.summary}</td>
                <td className="px-4 py-3 font-mono text-xs text-slate-400">{alert.created_at}</td>
              </tr>
            ))}
            {alerts.length === 0 && (
              <tr>
                <td colSpan="7" className="px-4 py-8 text-center text-slate-500">
                  No threats detected yet. Run the attack simulator or inject packets.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
