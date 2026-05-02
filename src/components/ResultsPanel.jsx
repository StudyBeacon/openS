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
  const counts = countBySeverity(results.findings);

  return (
    <div className="h-full bg-gray-900 overflow-auto p-6 space-y-6">
      {/* Risk Header */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <div className="flex items-end justify-between">
          <div>
            <div className="text-6xl font-bold text-green-400 mb-2">
              {results.risk_score}
            </div>
            <p className="text-gray-400 text-sm">Risk Score</p>
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
          <p className="text-gray-400 text-sm leading-relaxed">{results.summary}</p>
        </div>

        <div>
          <p className="text-gray-300 font-semibold mb-2 text-sm">Reasoning</p>
          <p className="text-gray-400 text-sm leading-relaxed">{results.reasoning}</p>
        </div>
      </div>

      {/* Findings List */}
      {results.findings && results.findings.length > 0 ? (
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-gray-300">
            Findings ({results.findings.length})
          </h3>
          {results.findings.map((finding, idx) => (
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

              {/* Description */}
              <div>
                <p className="text-gray-400 text-sm">{finding.description}</p>
              </div>

              {/* Fix Suggestion */}
              {finding.fix && (
                <div className="bg-green-900/20 border border-green-700/50 rounded p-3">
                  <p className="text-green-300 text-xs font-semibold uppercase tracking-wide mb-2">
                    Fix
                  </p>
                  <p className="text-green-200 text-sm">{finding.fix}</p>
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
