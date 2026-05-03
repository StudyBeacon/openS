import { useState } from 'react';
import { runLiveScan } from '../api';

export default function LiveURLScan({ onScan, scanning }) {
  const [url, setUrl] = useState('');
  const [depth, setDepth] = useState(2);
  const [confirmed, setConfirmed] = useState(false);
  const [localError, setLocalError] = useState(null);

  const handleStartScan = async (e) => {
    e.preventDefault();
    if (!confirmed) {
      setLocalError('You must confirm you have permission to test this website.');
      return;
    }
    if (!url.startsWith('http')) {
      setLocalError('Please enter a valid URL starting with http:// or https://');
      return;
    }
    setLocalError(null);
    onScan(url, depth);
  };

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 p-8 max-w-2xl mx-auto space-y-8">
      <div className="text-center">
        <div className="text-5xl mb-4">🌐</div>
        <h2 className="text-2xl font-bold text-gray-100">Safe Live Scan</h2>
        <p className="text-gray-400 mt-2">Legal, safety-constrained DAST explorer.</p>
      </div>

      <form onSubmit={handleStartScan} className="space-y-6">
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-2">Target URL</label>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={scanning}
            placeholder="http://testphp.vulnweb.com"
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-gray-100 focus:ring-2 focus:ring-green-500 focus:border-transparent outline-none transition-all"
          />
          <p className="text-gray-500 text-[10px] mt-1 italic">Allowed: testphp.vulnweb.com, localhost, *.test</p>
        </div>

        <div className="flex items-center gap-3 bg-gray-800/50 p-4 rounded-lg border border-gray-700">
          <input
            type="checkbox"
            id="confirm-perm"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
            className="w-5 h-5 accent-green-500"
          />
          <label htmlFor="confirm-perm" className="text-sm text-gray-300 font-medium cursor-pointer">
            I confirm I have permission to test this website.
          </label>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Crawl Depth</label>
            <input
              type="number"
              min="1"
              max="2"
              value={depth}
              onChange={(e) => setDepth(parseInt(e.target.value))}
              disabled={scanning}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-gray-100 outline-none"
            />
          </div>
        </div>

        <div className="bg-red-900/10 border border-red-900/30 rounded-lg p-4">
          <p className="text-red-300 text-xs font-bold uppercase tracking-widest mb-1 flex items-center gap-2">
            <span>🛡️</span> Safety Constraint Engaged
          </p>
          <p className="text-red-200/70 text-xs leading-relaxed">
             This tool strictly respects <span className="font-bold underline">robots.txt</span> and only targets specific educational platforms or local development environments. Rate limiting is active (1 req/sec).
          </p>
        </div>

        {localError && <p className="text-red-400 text-xs text-center">{localError}</p>}

        <button
          type="submit"
          disabled={scanning || !url || !confirmed}
          className={`w-full py-4 rounded-lg font-bold text-lg transition-all flex items-center justify-center gap-3 ${
            scanning || !confirmed
              ? 'bg-gray-700 text-gray-400 cursor-not-allowed' 
              : 'bg-green-600 hover:bg-green-500 text-white shadow-lg shadow-green-900/30'
          }`}
        >
          {scanning ? (
             <>
               <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
               Scanning Target...
             </>
          ) : (
             'Start Safe Scan'
          )}
        </button>
      </form>

      <div className="pt-8 border-t border-gray-800 space-y-4">
        <h3 className="text-gray-300 font-bold flex items-center gap-2">
           <span>🧪</span> Manual Payload Test
        </h3>
        <p className="text-gray-500 text-xs">Test a specific URL + parameter with your own payload.</p>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
           <input 
              type="text" 
              placeholder="Parameter Name (e.g. id)"
              id="manual-param"
              className="bg-gray-800 border border-gray-700 rounded p-2 text-xs text-gray-200 outline-none"
           />
           <select 
              id="manual-type"
              className="bg-gray-800 border border-gray-700 rounded p-2 text-xs text-gray-200 outline-none"
           >
              <option value="sqli">SQL Injection</option>
              <option value="xss">XSS</option>
           </select>
           <input 
              type="text" 
              placeholder="Custom Payload"
              id="manual-payload"
              className="bg-gray-800 border border-gray-700 rounded p-2 text-xs text-gray-200 outline-none col-span-full"
           />
        </div>

        <button 
          onClick={async () => {
             const url = document.querySelector('input[placeholder="http://testphp.vulnweb.com"]').value;
             const param = document.getElementById('manual-param').value;
             const payload = document.getElementById('manual-payload').value;
             const type = document.getElementById('manual-type').value;
             if (!url || !param || !payload) return alert('Please fill all manual test fields.');
             
             try {
                const res = await fetch('/api/test-target', {
                   method: 'POST',
                   headers: {'Content-Type': 'application/json'},
                   body: JSON.stringify({ url, param, payload, type })
                });
                const data = await res.json();
                if (data.vulnerable) {
                   alert(`⚠️ VULNERABLE!\nTarget: ${data.target}\n\nSnippet: ${data.snippet.substring(0, 200)}...`);
                } else {
                   alert("✅ No vulnerability detected with this payload.");
                }
             } catch(e) { alert("Test failed: " + e.message); }
          }}
          className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-bold transition-all"
        >
          Test Single Vector
        </button>
      </div>

      <div className="pt-4 border-t border-gray-800">
        <ul className="text-xs text-gray-500 space-y-2">
          <li className="flex gap-2"><span>✅</span> Checks for Reflected XSS</li>
          <li className="flex gap-2"><span>✅</span> Error-based SQL Injection testing</li>
          <li className="flex gap-2"><span>✅</span> Shell Command Injection (Blind & Direct)</li>
          <li className="flex gap-2"><span>✅</span> Automatic Form & Parameter Discovery</li>
        </ul>
      </div>
    </div>
  );
}
