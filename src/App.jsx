import { useState, useEffect } from 'react';
import { checkHealth } from '@/api';
import CodeEditor from './components/CodeEditor';
import FileUpload from './components/FileUpload';
import ResultsPanel from './components/ResultsPanel';

export default function App() {
  // State management
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('python');
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [activeTab, setActiveTab] = useState('editor');
  const [engineOnline, setEngineOnline] = useState(false);

  // Load history from localStorage and check engine health on mount
  useEffect(() => {
    // Load history
    const savedHistory = localStorage.getItem('openmythos_history');
    if (savedHistory) {
      try {
        setHistory(JSON.parse(savedHistory));
      } catch (e) {
        console.error('Failed to load history from localStorage:', e);
      }
    }

    // Check engine health
    checkEngineHealth();
  }, []);

  // Check if Ollama engine is online
  const checkEngineHealth = async () => {
    try {
      const health = await checkHealth();
      setEngineOnline(health.status === 'ok' && health.ollama);
    } catch (err) {
      console.error('Health check failed:', err);
      setEngineOnline(false);
    }
  };

  // Save history to localStorage (max 20 items)
  const saveHistory = (newHistory) => {
    const limited = newHistory.slice(0, 20);
    setHistory(limited);
    localStorage.setItem('openmythos_history', JSON.stringify(limited));
  };

  // Handle scan completion
  const handleScanComplete = (result) => {
    setResults(result);
    setError(null);
    saveHistory([result, ...history]);
  };

  // Handle scan error
  const handleScanError = (err) => {
    const errorMessage = err.response?.data?.detail || err.message || 'Scan failed';
    setError(errorMessage);
    setResults(null);
  };

  // Clear error on tab change
  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setError(null);
  };

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-gray-100 font-sans">
      {/* Navbar */}
      <nav className="border-b border-gray-800 bg-gray-900 px-8 py-4 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <span className="text-2xl">🔍</span>
          <h1 className="text-2xl font-bold text-green-400 tracking-wider">OpenMythos</h1>
        </div>

        {/* Engine Status Badge */}
        <div className="flex items-center gap-2">
          <div
            className={`w-3 h-3 rounded-full transition-colors ${
              engineOnline ? 'bg-green-400 shadow-lg shadow-green-400/50' : 'bg-red-500'
            }`}
          ></div>
          <span className="text-sm text-gray-400">
            {engineOnline ? 'Engine Online' : 'Engine Offline'}
          </span>
        </div>
      </nav>

      {/* Error Banner */}
      {error && (
        <div className="bg-red-900/20 border-l-4 border-red-500 px-8 py-3 text-red-200 flex justify-between items-center">
          <span>{error}</span>
          <button
            onClick={() => setError(null)}
            className="text-red-300 hover:text-red-100"
          >
            ✕
          </button>
        </div>
      )}

      {/* Tab Bar */}
      <div className="border-b border-gray-800 bg-gray-900 px-8 flex gap-8">
        {[
          { id: 'editor', label: 'Code Editor' },
          { id: 'files', label: 'File Upload' },
          { id: 'github', label: 'GitHub Scan' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => handleTabChange(tab.id)}
            className={`py-4 px-2 transition-all border-b-2 ${
              activeTab === tab.id
                ? 'border-green-400 text-green-400 font-semibold'
                : 'border-transparent text-gray-400 hover:text-gray-300'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Main Content Area - Two Columns */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Panel - Input */}
        <div className="flex-1 border-r border-gray-800 overflow-auto">
          {activeTab === 'editor' && (
            <CodeEditor
              code={code}
              setCode={setCode}
              language={language}
              setLanguage={setLanguage}
              scanning={scanning}
              setScanning={setScanning}
              onScanComplete={handleScanComplete}
              onScanError={handleScanError}
              engineOnline={engineOnline}
            />
          )}

          {activeTab === 'files' && (
            <FileUpload
              scanning={scanning}
              setScanning={setScanning}
              onScanComplete={handleScanComplete}
              onScanError={handleScanError}
              engineOnline={engineOnline}
            />
          )}

          {activeTab === 'github' && (
            <div className="flex items-center justify-center h-full text-gray-500">
              <div className="text-center">
                <div className="text-4xl mb-4">🚀</div>
                <p>GitHub integration coming soon...</p>
              </div>
            </div>
          )}
        </div>

        {/* Right Panel - Results */}
        <div className="flex-1 overflow-auto bg-gray-900">
          <ResultsPanel
            results={results}
            scanning={scanning}
            history={history}
          />
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-gray-800 bg-gray-900 px-8 py-3 text-center text-xs text-gray-600">
        Powered by DeepSeek Coder + Ollama • 100% Local • Zero Data Sent
      </footer>
    </div>
  );
}
