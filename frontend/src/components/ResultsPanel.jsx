export default function ResultsPanel({ results, scanning }) {
  /**
   * Get severity badge color
   */
  const getSeverityColor = (severity) => {
    const sev = severity?.toLowerCase();
    if (sev === 'critical') return 'bg-red-900 text-red-200';
    if (sev === 'high') return 'bg-orange-900 text-orange-200';
    if (sev === 'medium') return 'bg-yellow-900 text-yellow-200';
    return 'bg-green-900 text-green-200';
  };

  /**
   * Get risk level badge color
   */
  const getRiskLevelColor = (level) => {
    const lev = level?.toLowerCase();
    if (lev === 'critical') return 'bg-red-900 text-red-200 border-red-700';
    if (lev === 'high') return 'bg-orange-900 text-orange-200 border-orange-700';
    if (lev === 'medium') return 'bg-yellow-900 text-yellow-200 border-yellow-700';
    return 'bg-green-900 text-green-200 border-green-700';
  };

  /**
   * Count findings by severity
   */
  const countBySeverity = (findings) => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings?.forEach((f) => {
      const sev = f.severity?.toLowerCase() || 'low';
      if (counts[sev] !== undefined) counts[sev]++;
    });
    return counts;
  };

  // Loading state
  if (scanning) {
    return (
      <div className="flex flex-col items-center justify-center h-full bg-gray-900 p-6">
        <div className="mb-6">
          <div className="w-16 h-16 border-4 border-green-400 rounded-full animate-pulse"></div>
        </div>
        <h2 className="text-xl font-semibold text-green-400 mb-2">
          Analyzing with DeepSeek Coder...
        </h2>
        <p className="text-gray-400 text-sm">Running locally on your machine</p>
      </div>
    );
  }

  // Empty state
  if (!results) {
    return (
      <div className="flex flex-col items-center justify-center h-full bg-gray-900 p-6">
        <div className="text-6xl mb-4">🔒</div>
        <h2 className="text-xl font-semibold text-gray-300 mb-2">
          No scan results yet
        </h2>
        <p className="text-gray-500 text-sm">Run a scan to see results here</p>
      </div>
    );
  }

  // Results state
  const vulnerabilities = results.vulnerabilities || results.findings || [];
  const counts = results.summary && typeof results.summary === 'object' && results.summary.critical !== undefined 
    ? results.summary 
    : countBySeverity(vulnerabilities);

  const metadata = results.metadata || {};

  const handleDownloadPDF = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/report/pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(results),
      });
      if (!response.ok) throw new Error('Failed to generate PDF');
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `openmythos_report_${new Date().getTime()}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (error) {
      console.error('Error downloading PDF:', error);
      alert('Failed to download PDF report.');
    }
  };

  return (
    <div className="h-full bg-gray-900 overflow-auto p-6 space-y-6">
      {/* Risk Header */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <div className="flex items-end justify-between">
          <div className="flex items-center gap-8">
            <div>
              <div className="text-6xl font-bold text-green-400 mb-2">
                {results.risk_score}
              </div>
              <p className="text-gray-400 text-sm">Risk Score</p>
            </div>
            
            <button 
              onClick={handleDownloadPDF}
              className="mt-4 flex items-center gap-2 bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg font-semibold text-sm transition-all shadow-lg shadow-green-900/20"
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              PDF Report
            </button>
          </div>
          <div className="flex flex-col gap-3 items-end">
            <span
              className={`${getRiskLevelColor(
                results.risk_level
              )} px-4 py-2 rounded-full font-semibold text-sm capitalize border`}
            >
              {results.risk_level}
            </span>
            <span className="text-gray-500 text-xs">{results.scan_time_ms}ms scan time</span>
          </div>
        </div>
      </div>

      {/* Stats Row - Findings by Severity */}
      <div className="grid grid-cols-4 gap-3">
        <div className="bg-red-900/30 border border-red-700/50 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-red-300">{counts.critical}</div>
          <div className="text-xs text-red-200 mt-1">Critical</div>
        </div>
        <div className="bg-orange-900/30 border border-orange-700/50 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-orange-300">{counts.high}</div>
          <div className="text-xs text-orange-200 mt-1">High</div>
        </div>
        <div className="bg-yellow-900/30 border border-yellow-700/50 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-yellow-300">{counts.medium}</div>
          <div className="text-xs text-yellow-200 mt-1">Medium</div>
        </div>
        <div className="bg-green-900/30 border border-green-700/50 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-green-300">{counts.low}</div>
          <div className="text-xs text-green-200 mt-1">Low</div>
        </div>
      </div>

      {/* AI Analysis Card */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 space-y-4 relative">
        <div className="absolute top-4 right-4 bg-green-900/60 text-green-300 text-xs px-3 py-1 rounded-full border border-green-700/50 font-semibold">
          DeepSeek Local
        </div>

        <div className="flex items-center gap-3 mb-4 pr-32">
          <span
            className={`${getSeverityColor(
              results.verdict === 'vulnerable' ? 'critical' : 'low'
            )} px-3 py-1 rounded text-xs font-semibold capitalize`}
          >
            {results.verdict}
          </span>
          <span className="text-gray-400 text-sm">
            Confidence:{' '}
            <span className="text-green-400 font-semibold text-base">{results.confidence}%</span>
          </span>
        </div>

        <div>
          <p className="text-gray-300 font-semibold mb-2 text-sm">Summary</p>
          <div className="text-gray-400 text-sm leading-relaxed">
            {typeof (metadata.ai_summary || results.summary_text) === 'string' 
              ? (metadata.ai_summary || results.summary_text || 'Deep analysis complete. Check the findings list below for specific security risks.') 
              : 'Detailed analysis results are available in the findings list.'}
          </div>
        </div>

        <div>
          <p className="text-gray-300 font-semibold mb-2 text-sm">Reasoning</p>
          <div className="text-gray-400 text-sm leading-relaxed whitespace-pre-wrap">
            {typeof results.reasoning === 'string' ? results.reasoning : JSON.stringify(results.reasoning, null, 2)}
          </div>
          {metadata.raw_ai_response && (
            <div className="mt-4 p-2 bg-black/40 border border-gray-700 rounded text-[10px] text-gray-500 overflow-hidden text-ellipsis italic">
               Note: System successfully extracted findings from a truncated model response.
            </div>
          )}
        </div>
      </div>

      {/* Findings List */}
      {vulnerabilities.length > 0 ? (
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-gray-300">
            Findings ({vulnerabilities.length})
          </h3>
          {vulnerabilities.map((finding, idx) => (
            <div key={idx} className="bg-gray-800 border border-gray-700 rounded-lg p-5 space-y-3">
              {/* Finding Header */}
              <div className="flex items-center gap-3 flex-wrap">
                <span
                  className={`${getSeverityColor(
                    finding.severity
                  )} px-2 py-1 rounded text-xs font-semibold uppercase tracking-wide`}
                >
                  {finding.severity}
                </span>
                {finding.source && (
                  <span className="bg-gray-700 text-gray-300 px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider border border-gray-600">
                    {finding.source}
                  </span>
                )}
                <span className="text-gray-200 font-semibold">{finding.type}</span>
                {finding.line && (
                  <span className="text-gray-500 text-sm">Line {finding.line}</span>
                )}
              </div>

              {/* Code Snippet */}
              {finding.code_snippet && (
                <div className="bg-gray-950 border border-gray-700 rounded p-3 overflow-x-auto">
                  <code className="text-green-300 text-xs font-mono break-words">
                    {finding.code_snippet}
                  </code>
                </div>
              )}

              {/* Taint Flow Path (Visual Trail) */}
              {finding.taint_path && finding.taint_path.length > 0 && (
                <div className="border-l-2 border-gray-700 pl-4 py-1 space-y-2">
                  <p className="text-gray-500 text-[10px] uppercase font-bold tracking-widest mb-2">Taint Flow Trail</p>
                  {finding.taint_path.map((step, sIdx) => {
                    const isSource = step.startsWith('SOURCE:');
                    const isSink = step.startsWith('SINK:');
                    return (
                      <div key={sIdx} className="flex items-start gap-2">
                        <div className={`mt-1.5 w-2 h-2 rounded-full flex-shrink-0 ${isSource ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : isSink ? 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]' : 'bg-blue-500'}`} />
                        <span className={`text-[11px] font-mono leading-tight ${isSource ? 'text-green-400 font-bold' : isSink ? 'text-red-400 font-bold' : 'text-gray-400'}`}>
                          {step}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Description */}
              <div>
                <p className="text-gray-400 text-sm">{finding.description}</p>
              </div>

              {/* Exploitation Example */}
              {finding.exploitation && (
                <div className="bg-red-900/10 border border-red-900/30 rounded p-3">
                  <p className="text-red-300 text-[10px] font-bold uppercase tracking-widest mb-2">
                    Exploitation Example
                  </p>
                  <p className="text-red-200/80 text-xs italic">{finding.exploitation}</p>
                </div>
              )}

              {/* Fix Suggestion & Corrected Code */}
              {finding.fix && (
                <div className="bg-green-900/20 border border-green-700/50 rounded p-4 space-y-3">
                  <div>
                    <p className="text-green-300 text-[10px] font-bold uppercase tracking-widest mb-1">
                      Recommended Fix
                    </p>
                    <p className="text-green-100 text-sm">{finding.fix}</p>
                  </div>
                  
                  {finding.corrected_code && (
                    <div className="mt-2">
                      <p className="text-green-400/60 text-[9px] font-bold uppercase tracking-widest mb-1">
                        Corrected Code
                      </p>
                      <div className="bg-gray-950 rounded p-2 border border-green-900/30">
                        <code className="text-green-400 text-xs font-mono">{finding.corrected_code}</code>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 text-center">
          <p className="text-gray-300 font-semibold mb-1">✓ No vulnerabilities found!</p>
          <p className="text-gray-500 text-sm">This code appears to be safe.</p>
        </div>
      )}
    </div>
  );
}
