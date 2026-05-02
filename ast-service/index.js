import express from 'express';
import cors from 'cors';
import { analyzeCode } from './analyzer.js';

const app = express();
const PORT = 8001;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

/**
 * POST /analyze
 * Accepts {code, language}, analyzes for vulnerabilities
 */
app.post('/analyze', async (req, res) => {
  try {
    const { code, language } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }

    if (!language) {
      return res.status(400).json({ error: 'Language is required' });
    }

    const findings = analyzeCode(code, language);

    res.json({ findings });
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Analysis failed', details: error.message });
  }
});

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Start server
app.listen(PORT, () => {
  console.log(`AST Analyzer service running on port ${PORT}`);
});
