import { useState, useEffect } from 'react';
import { checkHealth, scanCode, scanFiles } from './api';
import CodeEditor from './components/CodeEditor';
import FileUpload from './components/FileUpload';
import ResultsPanel from './components/ResultsPanel';

export default function App() {
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('python');
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [activeTab, setActiveTab] = useState('editor');
  const [engines, setEngines] = useState({ rule: true, ast: false, ai: false });

  useEffect(() => {
    const saved = localStorage.getItem('openmythos_history');
    if (saved) try { setHistory(JSON.parse(saved)); } catch(e) {}
    
    const checkSystems = async () => {
      try {
        const h = await checkHealth();
        setEngines({ rule: true, ast: h.ast, ai: h.ollama });
      } catch {
        setEngines({ rule: false, ast: false, ai: false });
      }
    };
    
    checkSystems();
    const interval = setInterval(checkSystems, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleScan = async () => {
    if (!code.trim()) return;
    setScanning(true);
    setError(null);
    try {
      const result = await scanCode(code, language);
      setResults(result);
      const newHistory = [result, ...history].slice(0, 20);
      setHistory(newHistory);
      localStorage.setItem('openmythos_history', JSON.stringify(newHistory));
    } catch(err) {
      setError(err.response?.data?.detail || err.message || 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const handleFileScan = async (files) => {
    setScanning(true);
    setError(null);
    try {
      const result = await scanFiles(files);
      setResults(result);
    } catch(err) {
      setError(err.message || 'File scan failed');
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-gray-100">
      <nav className="border-b border-gray-800 bg-gray-900 px-8 py-4 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <span className="text-2xl">🔍</span>
          <h1 className="text-2xl font-bold bg-gradient-to-r from-green-400 to-blue-500 bg-clip-text text-transparent">OpenMythos v2</h1>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5 px-3 py-1 bg-gray-800 rounded-full border border-gray-700">
            <div className={`w-2 h-2 rounded-full ${engines.rule ? 'bg-green-400 shadow-[0_0_8px_rgba(74,222,128,0.5)]' : 'bg-red-500'}`}></div>
            <span className="text-[10px] font-bold text-gray-400 uppercase tracking-tighter">Rule</span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1 bg-gray-800 rounded-full border border-gray-700">
            <div className={`w-2 h-2 rounded-full ${engines.ast ? 'bg-green-400 shadow-[0_0_8px_rgba(74,222,128,0.5)]' : 'bg-red-500'}`}></div>
            <span className="text-[10px] font-bold text-gray-400 uppercase tracking-tighter">AST</span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1 bg-gray-800 rounded-full border border-gray-700">
            <div className={`w-2 h-2 rounded-full ${engines.ai ? 'bg-green-400 shadow-[0_0_8px_rgba(74,222,128,0.5)]' : 'bg-red-500'}`}></div>
            <span className="text-[10px] font-bold text-gray-400 uppercase tracking-tighter">AI</span>
          </div>
        </div>
      </nav>

      {error && (
        <div className="bg-red-900/20 border-l-4 border-red-500 px-8 py-3 text-red-200 flex justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)}>✕</button>
        </div>
      )}

      <div className="border-b border-gray-800 bg-gray-900 px-8 flex gap-8">
        {[{id:'editor',label:'Code Editor'},{id:'files',label:'File Upload'},{id:'github',label:'GitHub Scan'}].map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            className={`py-4 px-2 border-b-2 transition-all ${activeTab === tab.id ? 'border-green-400 text-green-400 font-semibold' : 'border-transparent text-gray-400'}`}>
            {tab.label}
          </button>
        ))}
      </div>

      <div className="flex-1 flex overflow-hidden">
        <div className="flex-1 border-r border-gray-800 overflow-auto p-4">
          {activeTab === 'editor' && (
            <CodeEditor code={code} setCode={setCode} language={language} setLanguage={setLanguage} onScan={handleScan} scanning={scanning} />
          )}
          {activeTab === 'files' && (
            <FileUpload onScan={handleFileScan} scanning={scanning} results={Array.isArray(results) ? results : null} />
          )}
          {activeTab === 'github' && (
            <div className="flex items-center justify-center h-full text-gray-500">
              <div className="text-center"><div className="text-4xl mb-4">🚀</div><p>GitHub integration coming soon...</p></div>
            </div>
          )}
        </div>
        <div className="flex-1 overflow-auto">
          <ResultsPanel results={results} scanning={scanning} />
        </div>
      </div>

      <footer className="border-t border-gray-800 bg-gray-900 px-8 py-3 text-center text-xs text-gray-600">
        Powered by DeepSeek Coder + Ollama • 100% Local • Zero Data Sent
      </footer>
    </div>
  );
}
