import React, { useState } from 'react';
import Editor from '@monaco-editor/react';

const SAMPLE_SNIPPETS = {
  'SQL Injection': {
    language: 'python',
    code: `import sqlite3

def search_user(username):
    db = sqlite3.connect('users.db')
    cursor = db.cursor()

    # Vulnerable: string concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)

    return cursor.fetchall()

# Attacker input: admin' OR '1'='1
result = search_user(input("Enter username: "))`,
  },
  'Command Injection': {
    language: 'python',
    code: `import os

def process_file(filename):
    # Vulnerable: unsanitized user input in shell command
    user_input = input("Enter filename to process: ")
    command = "cat " + user_input

    os.system(command)

# Attacker input: users.txt; rm -rf /
process_file(input())`,
  },
  'XSS + Eval': {
    language: 'javascript',
    code: `function renderUserContent(userInput) {
    // Vulnerable: innerHTML allows XSS attacks
    const container = document.getElementById('content');
    container.innerHTML = '<p>' + userInput + '</p>';
}

function executeExpression(expr) {
    // Vulnerable: eval executes arbitrary code
    const result = eval(expr);
    return result;
}

// Attacker input: <img src=x onerror="alert('XSS')">
renderUserContent(userInput);

// Attacker input: require('fs').unlinkSync('/important.file')
executeExpression(userInput);`,
  },
  'Insecure Crypto': {
    language: 'python',
    code: `import hashlib

def hash_password(password):
    # Vulnerable: MD5 is cryptographically broken
    md5_hash = hashlib.md5(password.encode())
    return md5_hash.hexdigest()

def hash_user_data(data):
    # Vulnerable: no salt, predictable
    user_hash = hashlib.md5(data.encode()).hexdigest()
    return user_hash

# Should use bcrypt, scrypt, or Argon2 instead
password = input("Enter password: ")
hashed = hash_password(password)`,
  },
  'Clean Code': {
    language: 'python',
    code: `import hashlib
import secrets

def hash_password(password: str) -> str:
    """Hash password using bcrypt with salt."""
    # Safe: use proper password hashing
    import bcrypt
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

def search_user(username: str) -> list:
    """Search user by username using parameterized query."""
    import sqlite3

    db = sqlite3.connect('users.db')
    cursor = db.cursor()

    # Safe: parameterized query prevents SQL injection
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))

    return cursor.fetchall()

def render_content(user_input: str) -> str:
    """Safely render user content with escaping."""
    # Safe: use text content, escape special characters
    from html import escape
    return escape(user_input)`,
  },
};

export default function CodeEditor({
  code,
  setCode,
  language,
  setLanguage,
  onScan,
  scanning,
}) {
  const lineCount = code.split('\n').length;
  const charCount = code.length;

  const handleSnippetLoad = (snippetKey) => {
    const snippet = SAMPLE_SNIPPETS[snippetKey];
    setCode(snippet.code);
    setLanguage(snippet.language);
  };

  return (
    <div className="flex flex-col gap-4 bg-gray-900 rounded-lg overflow-hidden border border-gray-700">
      {/* Top Bar */}
      <div className="flex items-center justify-between bg-gray-800 px-6 py-3 border-b border-gray-700">
        <label className="text-sm font-semibold text-gray-300 uppercase tracking-wide">
          Code Input
        </label>
        <select
          value={language}
          onChange={(e) => setLanguage(e.target.value)}
          className="px-3 py-2 bg-gray-700 text-white rounded border border-gray-600 hover:border-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
        >
          <option value="python">Python</option>
          <option value="javascript">JavaScript</option>
          <option value="typescript">TypeScript</option>
          <option value="java">Java</option>
          <option value="go">Go</option>
          <option value="cpp">C++</option>
        </select>
      </div>

      {/* Sample Snippets Bar */}
      <div className="flex flex-wrap gap-2 px-6 py-3 bg-gray-850 border-b border-gray-700">
        {Object.keys(SAMPLE_SNIPPETS).map((snippetKey) => (
          <button
            key={snippetKey}
            onClick={() => handleSnippetLoad(snippetKey)}
            className="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 text-gray-200 rounded border border-gray-600 hover:border-gray-500 transition-colors"
          >
            {snippetKey}
          </button>
        ))}
      </div>

      {/* Editor Area */}
      <div className="flex-1 px-6 py-4">
        <Editor
          height="500px"
          language={language}
          value={code}
          onChange={(value) => setCode(value || '')}
          theme="vs-dark"
          options={{
            lineNumbers: 'on',
            fontSize: 14,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            automaticLayout: true,
            tabSize: 2,
            wordWrap: 'on',
          }}
        />
      </div>

      {/* Bottom Bar */}
      <div className="flex items-center justify-between bg-gray-800 px-6 py-3 border-t border-gray-700">
        <div className="text-xs text-gray-400 space-x-4">
          <span>Lines: {lineCount}</span>
          <span>Characters: {charCount}</span>
        </div>
        <button
          onClick={onScan}
          disabled={scanning}
          className={`px-6 py-2 rounded font-semibold text-sm transition-colors ${
            scanning
              ? 'bg-gray-600 text-gray-300 cursor-not-allowed'
              : 'bg-green-600 hover:bg-green-700 text-white'
          }`}
        >
          {scanning ? 'Scanning...' : 'Scan for Vulnerabilities'}
        </button>
      </div>
    </div>
  );
}
