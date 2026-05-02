import React, { useState, useRef } from 'react';
import { Upload, X } from 'lucide-react';

const LANGUAGE_MAP = {
  py: 'Python',
  js: 'JavaScript',
  ts: 'TypeScript',
  java: 'Java',
  go: 'Go',
  cpp: 'C++',
  c: 'C',
};

const getRiskColor = (level) => {
  switch (level?.toLowerCase()) {
    case 'critical':
      return 'bg-red-900 text-red-200 border border-red-700';
    case 'high':
      return 'bg-orange-900 text-orange-200 border border-orange-700';
    case 'medium':
      return 'bg-yellow-900 text-yellow-200 border border-yellow-700';
    case 'low':
      return 'bg-blue-900 text-blue-200 border border-blue-700';
    default:
      return 'bg-gray-700 text-gray-200 border border-gray-600';
  }
};

const getLanguageFromExtension = (filename) => {
  const ext = filename.split('.').pop()?.toLowerCase();
  return LANGUAGE_MAP[ext] || 'Unknown';
};

const formatFileSize = (bytes) => {
  return (bytes / 1024).toFixed(2);
};

export default function FileUpload({ onScan, scanning, results }) {
  const [files, setFiles] = useState([]);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => {
    setDragOver(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);

    const droppedFiles = Array.from(e.dataTransfer.files);
    addFiles(droppedFiles);
  };

  const handleFileSelect = (e) => {
    const selectedFiles = Array.from(e.target.files || []);
    addFiles(selectedFiles);
  };

  const addFiles = (newFiles) => {
    const validExtensions = ['py', 'js', 'ts', 'java', 'go', 'cpp', 'c'];
    const filtered = newFiles.filter((file) => {
      const ext = file.name.split('.').pop()?.toLowerCase();
      return validExtensions.includes(ext);
    });

    setFiles((prevFiles) => [...prevFiles, ...filtered]);
    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const removeFile = (index) => {
    setFiles((prevFiles) => prevFiles.filter((_, i) => i !== index));
  };

  const handleScan = () => {
    onScan(files);
  };

  return (
    <div className="flex flex-col gap-6 bg-gray-900 rounded-lg border border-gray-700 p-6">
      {/* Drop Zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-colors ${
          dragOver
            ? 'border-green-500 bg-green-500 bg-opacity-10'
            : 'border-gray-600 bg-gray-800 hover:border-gray-500'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept=".py,.js,.ts,.java,.go,.cpp,.c"
          onChange={handleFileSelect}
          className="hidden"
        />

        <Upload className="w-12 h-12 mx-auto mb-3 text-gray-400" />
        <p className="text-gray-300 text-lg font-medium">
          Drop code files here or click to browse
        </p>
        <p className="text-gray-500 text-sm mt-2">
          Supported: Python, JavaScript, TypeScript, Java, Go, C++, C
        </p>

        {files.length > 0 && (
          <p className="text-green-400 text-sm mt-3 font-semibold">
            {files.length} file{files.length !== 1 ? 's' : ''} selected
          </p>
        )}
      </div>

      {/* File List */}
      {files.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">
            Selected Files
          </h3>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {files.map((file, index) => (
              <div
                key={index}
                className="flex items-center justify-between bg-gray-800 p-3 rounded border border-gray-700 hover:border-gray-600"
              >
                <div className="flex-1 min-w-0">
                  <p className="text-gray-200 font-medium truncate">
                    {file.name}
                  </p>
                  <div className="flex gap-3 mt-1 text-xs text-gray-400">
                    <span>{formatFileSize(file.size)} KB</span>
                    <span>
                      {getLanguageFromExtension(file.name)}
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => removeFile(index)}
                  className="ml-3 p-1 hover:bg-red-900 hover:bg-opacity-50 rounded transition-colors flex-shrink-0"
                  aria-label="Remove file"
                >
                  <X className="w-5 h-5 text-red-400 hover:text-red-300" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Scan Button */}
      <div className="flex justify-end">
        <button
          onClick={handleScan}
          disabled={files.length === 0 || scanning}
          className={`px-6 py-2 rounded font-semibold text-sm transition-colors ${
            files.length === 0 || scanning
              ? 'bg-gray-600 text-gray-300 cursor-not-allowed'
              : 'bg-green-600 hover:bg-green-700 text-white'
          }`}
        >
          {scanning ? 'Scanning...' : `Scan ${files.length} File${files.length !== 1 ? 's' : ''}`}
        </button>
      </div>

      {/* Results */}
      {Array.isArray(results) && results.length > 0 && (
        <div className="space-y-3 pt-4 border-t border-gray-700">
          <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">
            Scan Results
          </h3>
          <div className="grid gap-3">
            {results.map((result, index) => (
              <div
                key={index}
                className="bg-gray-800 p-4 rounded border border-gray-700 hover:border-gray-600"
              >
                <div className="flex items-start justify-between mb-2">
                  <p className="text-gray-200 font-medium truncate flex-1">
                    {result.filename}
                  </p>
                  <span
                    className={`ml-2 px-2 py-1 rounded text-xs font-semibold flex-shrink-0 ${getRiskColor(
                      result.riskLevel
                    )}`}
                  >
                    {result.riskLevel || 'N/A'}
                  </span>
                </div>

                <div className="flex items-center gap-4 text-sm text-gray-400">
                  <span>
                    Risk Score:{' '}
                    <span className="text-gray-300 font-semibold">
                      {result.riskScore !== undefined
                        ? `${result.riskScore}/100`
                        : 'N/A'}
                    </span>
                  </span>
                  <span>
                    Findings:{' '}
                    <span className="text-gray-300 font-semibold">
                      {result.findingCount || 0}
                    </span>
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
