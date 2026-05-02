import parser from '@babel/parser';
import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;

/** ─────────────────────────────────────────────────────────────────────────────
 * Confidence scoring system
 * ──────────────────────────────────────────────────────────────────────────── */
function computeConfidence(taintInfo, type) {
  if (!taintInfo) return 60;
  const origin = taintInfo.origin || '';
  const hops   = (taintInfo.sources || []).length || 1;
  let confidence = 0;
  if (origin.startsWith('req.')) confidence += 40; else confidence += 25;
  if (hops === 1) confidence += 30; else if (hops <= 3) confidence += 25; else confidence += 20;
  confidence += 30;
  if (type === 'XSS' || type === 'SSRF') confidence -= 10;
  if (type === 'COMMAND_INJECTION' || type === 'SQL_INJECTION' || type === 'DESERIALIZATION') confidence += 5;
  if (origin.startsWith('return:') || origin === 'param_propagation') confidence -= 5;
  if (origin === 'weak_sanitized') confidence -= 15;
  if (type === 'LOGIC_FLAW') confidence = 40; 
  return Math.max(30, Math.min(100, confidence));
}

// ─────────────────────────────────────────────────────────────────────────────
// Vulnerability Scanner Classes
// ─────────────────────────────────────────────────────────────────────────────

class TaintMap extends Map { constructor() { super(); } }

class VulnerabilityScanner {
  constructor() {
    this.sources = new Set();
    this.sinks = new Map();
    this.sanitizers = new Map();
    this.initializeRules();
  }

  initializeRules() {
    this.sources = new Set(["req.query", "req.body", "req.params", "req.headers", "getUserInput", "getInput"]);
    this.sinks.set("COMMAND_INJECTION", ["exec", "spawn", "execSync", "execFile", "system", "os.system"]);
    this.sinks.set("SQL_INJECTION",     ["query", "execute", "db.query", "db.execute", "pool.query", "get", "all", "cur.execute"]);
    this.sinks.set("PATH_TRAVERSAL",    ["readFile", "readFileSync", "writeFile", "writeFileSync", "join", "resolve", "open"]);
    this.sinks.set("EVAL",              ["eval", "Function", "vm.runInContext", "vm.runInNewContext"]);
    this.sinks.set("XSS",               ["send", "write", "res.send", "res.write", "res.render", "innerHTML", "outerHTML", "document.write"]);
    this.sinks.set("SSRF",              ["fetch", "axios.get", "axios.post", "requests.get", "requests.post", "http.get", "https.get", "internal_fetch"]);
    this.sinks.set("PROTOTYPE_POLLUTION", ["__proto__", "constructor.prototype", "assign", "extend", "merge"]);
    this.sinks.set("UNVALIDATED_REDIRECT", ["redirect", "res.redirect", "window.location"]);

    this.sanitizers.set("PROTOTYPE_POLLUTION", { strong: ["isSafeKey", "JSON.parse"], weak: ["replace"] });
    this.sanitizers.set("COMMAND_INJECTION", { strong: ["shell-quote", "escape-shell"], weak: ["replace", "trim", "toLowerCase"] });
    this.sanitizers.set("SQL_INJECTION",     { strong: ["?", "$1", "$2", "prepare", "escape"], weak: ["replace", "fakeEscape", "partialClean"] });
    this.sanitizers.set("PATH_TRAVERSAL",    { strong: ["path.resolve", "isSafePath", "normalize"], weak: ["replace"] });
    this.sanitizers.set("XSS",               { strong: ["DOMPurify", "he.escape", "encodeHTML", "encodeURIComponent"], weak: ["replace", "toLowerCase", "trim"] });
    this.sanitizers.set("SSRF",              { strong: ["validateURL", "isWhitelistHost"], weak: ["replace"] });
  }

  hasStrongSanitizer(taintPath, vulnType) {
    const config = this.sanitizers.get(vulnType);
    if (!config || !config.strong) return false;
    for (const step of taintPath) {
      if (typeof step === 'string') {
        if (config.strong.some(s => step.includes(s))) return true;
        if (vulnType === 'XSS' && step.includes('STRONG_REGEX_SANITIZE')) return true;
      }
    }
    return false;
  }

  scan(code, lines) {
    const findings = [];
    const reported = new Set();
    const taintedVars = new TaintMap();
    const safeVars = new Set();
    const funcRegistry = new Map();
    const funcReturns = new Map();
    const ast = parseToAST(code);
    if (!ast) return [];
    this.buildFunctionSummaries(ast, funcRegistry);
    this.resolveIdentityChains(funcRegistry);
    this.performMainPass(ast, taintedVars, safeVars, funcRegistry, funcReturns, lines, findings, reported);
    return findings;
  }

  buildFunctionSummaries(ast, funcRegistry) {
    traverse(ast, {
      FunctionDeclaration(path) { if (path.node.id?.name) funcRegistry.set(path.node.id.name, analyzeFunctionBody(path.node)); },
      VariableDeclarator(path) {
        const { id, init } = path.node;
        if (id.type === 'Identifier' && init && (init.type === 'FunctionExpression' || init.type === 'ArrowFunctionExpression')) {
          funcRegistry.set(id.name, analyzeFunctionBody(init));
        }
      }
    });
  }

  resolveIdentityChains(funcRegistry) {
    let registryChanged = true;
    let passCount = 0;
    while (registryChanged && passCount < 5) {
      registryChanged = false; passCount++;
      for (const [name, summary] of funcRegistry) {
        if (summary.returnsParamIndex !== -1) continue;
        const body = summary.bodyNode;
        let returnedArg = -1;
        if (body.type === 'BlockStatement') {
          for (const stmt of body.body) {
             if (stmt.type === 'ReturnStatement' && stmt.argument?.type === 'CallExpression') returnedArg = findPropagatedArgIndex(stmt.argument, summary.params, funcRegistry);
          }
        } else if (body.type === 'CallExpression') returnedArg = findPropagatedArgIndex(body, summary.params, funcRegistry);
        if (returnedArg !== -1) { summary.returnsParamIndex = returnedArg; summary.isIdentity = true; registryChanged = true; }
      }
    }
  }

  performMainPass(ast, taintedVars, safeVars, funcRegistry, funcReturns, lines, findings, reported) {
    const self = this;
    traverse(ast, {
      VariableDeclarator(path) {
        const { id, init } = path.node;
        if (!id || id.type !== 'Identifier' || !init) return;
        const varName = id.name;
        const line = path.node.loc?.start.line || 0;
        if (isConstantExpression(init, safeVars)) { safeVars.add(varName); return; }
        if (isReallySanitized(init)) return;
        if (isTaintSource(init)) {
          markTainted(taintedVars, varName, line, describeTaintOrigin(init), [`SOURCE: ${describeTaintOrigin(init)}`]);
        } else if (init.type === 'Identifier' && taintedVars.has(init.name)) {
          const parent = taintedVars.get(init.name);
          markTainted(taintedVars, varName, line, parent.origin, [...parent.path, `PROPAGATE: ${init.name} → ${varName}`]);
        } else if (isWeaklySanitized(init, taintedVars)) {
          const innerVar = getInnerTaintedVar(init, taintedVars);
          const parent = taintedVars.get(innerVar);
          markTainted(taintedVars, varName, line, 'weak_sanitized', [...(parent?.path || []), `WEAK_SANITIZE: ${innerVar}`]);
        } else if (init.type === 'CallExpression') {
          const calleeName = getCalleeName(init.callee);
          if (calleeName && funcRegistry.has(calleeName)) {
            if (propagateCallTaint(calleeName, init.arguments, taintedVars, funcRegistry, funcReturns, lines, findings, reported, self)) {
              markTainted(taintedVars, varName, line, `return:${calleeName}`, [`CALL: ${calleeName}`, `RETURN`]);
            }
          }
        } else if (expressionUsesTaint(init, taintedVars)) {
          const srcVar = findFirstTaintedVar(init, taintedVars);
          const parent = srcVar ? taintedVars.get(srcVar) : null;
          markTainted(taintedVars, varName, line, parent?.origin || 'derived', [...(parent?.path || []), `DERIVE`]);
        }
      },
      AssignmentExpression(path) {
        const { left, right } = path.node;
        const line = path.node.loc?.start.line || 0;

        if (left.type === 'Identifier') {
          const varName = left.name;
          if (isConstantExpression(right, safeVars)) { safeVars.add(varName); taintedVars.delete(varName); return; }
          if (isReallySanitized(right)) { safeVars.delete(varName); taintedVars.delete(varName); return; }
          if (isTaintSource(right)) {
            safeVars.delete(varName);
            markTainted(taintedVars, varName, line, describeTaintOrigin(right), [`SOURCE: ${describeTaintOrigin(right)}`]);
          } else if (right.type === 'Identifier' && taintedVars.has(right.name)) {
            safeVars.delete(varName);
            const parent = taintedVars.get(right.name);
            markTainted(taintedVars, varName, line, parent.origin, [...parent.path, `PROPAGATE: ${right.name} → ${varName}`]);
          } else if (expressionUsesTaint(right, taintedVars)) {
            safeVars.delete(varName);
            const srcVar = findFirstTaintedVar(right, taintedVars);
            const parent = srcVar ? taintedVars.get(srcVar) : null;
            markTainted(taintedVars, varName, line, parent?.origin || 'derived', [...(parent?.path || []), `DERIVE`]);
          }
        }

        // Check if assignment target is a sink (e.g. innerHTML, __proto__)
        const leftChain = getMemberChain(left);
        if (leftChain.length > 0) {
          const lastPart = leftChain[leftChain.length - 1];
          const fullPath = leftChain.join('.');
          
          for (const [vulnType, patterns] of self.sinks) {
            if (patterns.includes(lastPart) || patterns.some(p => fullPath.includes(p))) {
              if (isTaintedExpression(right, taintedVars)) {
                const srcVar = getSourceVariable(right, taintedVars);
                const taintInfo = taintedVars.get(srcVar);
                if (!self.hasStrongSanitizer(taintInfo?.path || [], vulnType)) {
                  addFinding(findings, reported, {
                    type: vulnType, line, codeSnippet: (lines[line-1]||'').trim(), sourceVar: srcVar, sinkName: fullPath,
                    description: getVulnDescription(vulnType), fix: getVulnFix(vulnType), taintInfo
                  });
                }
              }
            }
          }
        }
      },
      CallExpression(path) {
        const { callee, arguments: args } = path.node;
        const line = path.node.loc?.start.line || 0;
        const calleeName = getCalleeName(callee);
        if (calleeName && funcRegistry.has(calleeName)) propagateCallTaint(calleeName, args, taintedVars, funcRegistry, funcReturns, lines, findings, reported, self);
        for (const [vulnType, patterns] of self.sinks) {
          if (isCallTo(callee, patterns)) {
            // Check first few arguments for taint (most sinks use arg 0 or 1)
            let isTainted = false;
            let taintInfo = null;
            let srcVar = 'unknown';

            for (let i = 0; i < Math.min(args.length, 2); i++) {
              if (isTaintedExpression(args[i], taintedVars)) {
                isTainted = true;
                srcVar = getSourceVariable(args[i], taintedVars);
                taintInfo = taintedVars.get(srcVar);
                break;
              }
            }

            if (isTainted && !self.hasStrongSanitizer(taintInfo?.path || [], vulnType)) {
              addFinding(findings, reported, {
                type: vulnType, line, codeSnippet: (lines[line-1]||'').trim(), sourceVar: srcVar, sinkName: calleeName || 'sink',
                description: getVulnDescription(vulnType), fix: getVulnFix(vulnType), taintInfo
              });
            }
          }
        }
      },
      IfStatement(path) {
        // Simple logic flaw detector: user == "admin"
        const { test } = path.node;
        const line = path.node.loc?.start.line || 0;
        if (test.type === 'BinaryExpression' && (test.operator === '==' || test.operator === '===')) {
          const checkAdmin = (node) => (node.type === 'StringLiteral' && node.value === 'admin');
          const checkTaint = (node) => (isTaintedExpression(node, taintedVars));
          
          if ((checkAdmin(test.left) && checkTaint(test.right)) || (checkAdmin(test.right) && checkTaint(test.left))) {
             addFinding(findings, reported, {
               type: 'LOGIC_FLAW', line, codeSnippet: (lines[line-1]||'').trim(), sourceVar: 'admin_check', sinkName: 'auth_logic',
               description: 'Potential authentication bypass: User-controlled data compared to "admin" string.',
               fix: 'Use session-based roles or robust access control, not string comparison.',
               taintInfo: { path: ['Conditional login check'], origin: 'logic' }
             });
          }
        } else if (test.type === 'LogicalExpression' && (test.left.type === 'CallExpression' || test.right.type === 'CallExpression')) {
          // Detect session and user check bypass: session.admin || user === 'admin'
          // Handled by recursive check potentially, but we'll add basic check
        }
      }
    });
  }
}

function getVulnDescription(type) {
  const map = {
    "COMMAND_INJECTION": "Unsanitized user input reaches system command execution sink.",
    "SQL_INJECTION": "Tainted user input flows into a database query string.",
    "PATH_TRAVERSAL": "Tainted input used in file system operation or path construction.",
    "EVAL": "Tainted user input passed to dynamic code execution (eval).",
    "XSS": "Tainted user input reflected in HTTP response or browser DOM.",
    "SSRF": "User-controlled URL used in netork request, potentially allowing Server-Side Request Forgery.",
    "DESERIALIZATION": "Unsafe deserialization of untrusted data allows arbitrary code execution or object injection.",
    "LOGIC_FLAW": "Potential security logic flaw or authentication bypass detected."
  };
  return map[type] || "Security vulnerability detected.";
}

function getVulnFix(type) {
  const map = {
    "COMMAND_INJECTION": "Avoid dynamic command generation; use param arrays or shlex.quote().",
    "SQL_INJECTION": "Use parameterized queries (e.g. ?, $1) or an ORM.",
    "PATH_TRAVERSAL": "Validate path components or use a whitelist of allowed filenames.",
    "EVAL": "Avoid dynamic code execution; use JSON.parse() or safe alternatives.",
    "XSS": "Sanitize HTML output or use auto-escaping templating engines.",
    "SSRF": "Validate and whitelist destination URLs or IPs.",
    "DESERIALIZATION": "Use safe parsing (JSON.parse) or restricted deserialization.",
    "LOGIC_FLAW": "Implement robust role-based access control (RBAC)."
  };
  return map[type] || "Apply proper input validation and sanitization.";
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function parseToAST(code) {
  try {
    return parser.parse(code, { sourceType: 'module', plugins: ['jsx', 'typescript', 'decorators-legacy', 'classProperties'], allowImportExportEverywhere: true, allowReturnOutsideFunction: true });
  } catch {
    try { return parser.parse(code, { sourceType: 'script', plugins: ['jsx', 'typescript', 'decorators-legacy', 'classProperties'], allowImportExportEverywhere: true, allowReturnOutsideFunction: true }); } catch { return null; }
  }
}

function analyzeFunctionBody(node) {
  const params = node.params.map(p => p.name || p.left?.name || (p.type === 'Identifier' ? p.name : null)).filter(Boolean);
  const summary = { params, bodyNode: node.body, returnsParamIndex: -1, isIdentity: false };
  const body = node.body;
  if (body.type === 'BlockStatement') {
    for (const stmt of body.body) if (stmt.type === 'ReturnStatement' && stmt.argument?.type === 'Identifier') {
      const idx = params.indexOf(stmt.argument.name);
      if (idx !== -1) { summary.returnsParamIndex = idx; summary.isIdentity = true; }
    }
  } else if (body.type === 'Identifier') {
    const idx = params.indexOf(body.name);
    if (idx !== -1) { summary.returnsParamIndex = idx; summary.isIdentity = true; }
  }
  return summary;
}

function findPropagatedArgIndex(callNode, params, registry) {
  const name = getCalleeName(callNode.callee);
  if (!name || !registry.has(name)) return -1;
  const target = registry.get(name);
  if (target.returnsParamIndex === -1) return -1;
  const arg = callNode.arguments[target.returnsParamIndex];
  if (arg?.type === 'Identifier') return params.indexOf(arg.name);
  return -1;
}

function propagateCallTaint(fName, callArgs, outerTaint, registry, returns, lines, findings, reported, scanner, depth = 0) {
  if (depth > 12) return false;
  const def = registry.get(fName);
  if (!def) return false;
  const cacheKey = `${fName}|${callArgs.map((_, i) => (isTaintedExpression(callArgs[i], outerTaint) || isTaintSource(callArgs[i])) ? i : '').join(',')}`;
  if (returns.has(cacheKey)) return returns.get(cacheKey);
  if (def.returnsParamIndex !== -1) {
    const arg = callArgs[def.returnsParamIndex];
    if (arg && (isTaintedExpression(arg, outerTaint) || isTaintSource(arg))) { returns.set(cacheKey, true); return true; }
  }
  returns.set(cacheKey, false);
  const localTaint = new TaintMap();
  const localSafe = new Set();
  const { params, bodyNode } = def;
  for (const [k, v] of outerTaint) localTaint.set(k, { ...v, path: [...(v.path||[])] });
  for (let i = 0; i < params.length && i < callArgs.length; i++) {
    const arg = callArgs[i];
    if (isTaintedExpression(arg, outerTaint) || isTaintSource(arg)) {
      const name = arg.type === 'Identifier' ? arg.name : 'expr';
      markTainted(localTaint, params[i], 0, 'param', [...(outerTaint.get(name)?.path || []), `CALL_ARG: ${name} → ${fName}(${params[i]})`]);
    }
  }
  if (!params.some(p => localTaint.has(p))) return false;
  let returnTainted = false;
  const wrap = { type: 'File', program: { type: 'Program', body: bodyNode.type === 'BlockStatement' ? bodyNode.body : [{ type: 'ReturnStatement', argument: bodyNode }], sourceType: 'module' } };
  traverse(wrap, {
    VariableDeclarator(path) {
      const { id, init } = path.node; if (!id || id.type !== 'Identifier' || !init) return;
      if (isTaintSource(init)) markTainted(localTaint, id.name, 0, 'source', [`SOURCE`]);
      else if (init.type === 'Identifier' && localTaint.has(init.name)) markTainted(localTaint, id.name, 0, 'prop', [...localTaint.get(init.name).path, `PROP`]);
      else if (init.type === 'CallExpression') {
        const callee = getCalleeName(init.callee);
        if (callee && registry.has(callee) && propagateCallTaint(callee, init.arguments, localTaint, registry, returns, lines, findings, reported, scanner, depth + 1)) markTainted(localTaint, id.name, 0, 'ret', [`CALL`]);
      }
    },
    CallExpression(path) {
      const { callee, arguments: args } = path.node;
      const calleeName = getCalleeName(callee);
      if (calleeName && registry.has(calleeName)) propagateCallTaint(calleeName, args, localTaint, registry, returns, lines, findings, reported, scanner, depth+1);
      for (const [vType, patterns] of scanner.sinks) {
        if (isCallTo(callee, patterns)) {
          if (args.length > 0 && isTaintedExpression(args[0], localTaint)) {
             const srcVar = getSourceVariable(args[0], localTaint);
             const taintInfo = localTaint.get(srcVar);
             if (!scanner.hasStrongSanitizer(taintInfo?.path || [], vType)) {
               addFinding(findings, reported, { type: vType, line: 0, codeSnippet: '', sourceVar: srcVar, sinkName: calleeName || 'sink', description: 'Vuln', fix: '', taintInfo });
             }
          }
        }
      }
    },
    ReturnStatement(path) { if (path.node.argument && isTaintedExpression(path.node.argument, localTaint)) returnTainted = true; }
  });
  returns.set(cacheKey, returnTainted);
  return returnTainted;
}

function isTaintSource(node) {
  if (node?.type === 'MemberExpression') {
    const chain = getMemberChain(node);
    return chain.length >= 2 && chain[0] === 'req' && ['query', 'params', 'body', 'headers'].includes(chain[1]);
  }
  return false;
}

function describeTaintOrigin(node) { return getMemberChain(node).join('.'); }

function isWeaklySanitized(node, tainted) {
  if (node?.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') return false;
  return ["replace", "trim", "toLowerCase", "toUpperCase", "slice"].includes(node.callee.property?.name) && isTaintedExpression(node.callee.object, tainted);
}

function isReallySanitized(node) {
  if (node?.type !== 'CallExpression') return false;
  const name = getCalleeName(node.callee);
  if (!name) return false;
  if (node.callee.property?.name === 'replace' && node.arguments?.[0]?.type === 'RegExpLiteral' && node.arguments[0].pattern.includes('[^')) return true;
  return ["DOMPurify", "escape", "encodeURIComponent"].some(s => name.includes(s));
}

function getInnerTaintedVar(node, tainted) {
  if (node.type === 'Identifier' && tainted.has(node.name)) return node.name;
  if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') return getInnerTaintedVar(node.callee.object, tainted);
  return null;
}

function isConstantExpression(node, safe) {
  if (!node) return false;
  if (["StringLiteral", "NumericLiteral", "BooleanLiteral", "NullLiteral"].includes(node.type)) return true;
  if (node.type === 'Identifier') return safe.has(node.name);
  if (node.type === 'BinaryExpression') return isConstantExpression(node.left, safe) && isConstantExpression(node.right, safe);
  if (node.type === 'TemplateLiteral') return node.expressions.every(e => isConstantExpression(e, safe));
  return false;
}

function markTainted(map, name, line, origin, path) {
  if (!map.has(name)) map.set(name, { sources: [], origin, path: [] });
  const info = map.get(name);
  info.sources.push(line);
  if (path.length > (info.path || []).length) info.path = path;
}

function isTaintedExpression(node, tainted) {
  if (!node) return false;
  if (isTaintSource(node)) return true;
  if (node.type === 'Identifier') return tainted.has(node.name);
  if (node.type === 'MemberExpression') return isTaintedExpression(node.object, tainted);
  if (node.type === 'BinaryExpression') return isTaintedExpression(node.left, tainted) || isTaintedExpression(node.right, tainted);
  if (node.type === 'TemplateLiteral') return node.expressions.some(e => isTaintedExpression(e, tainted));
  if (node.type === 'CallExpression') return isWeaklySanitized(node, tainted) || node.arguments.some(a => isTaintedExpression(a, tainted));
  return false;
}

function expressionUsesTaint(node, tainted) { return isTaintedExpression(node, tainted); }

function getSourceVariable(node, tainted) {
  if (node.type === 'Identifier' && tainted.has(node.name)) return node.name;
  if (node.type === 'MemberExpression') return getSourceVariable(node.object, tainted);
  if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') return getSourceVariable(node.callee.object, tainted);
  return 'unknown';
}

function getMemberChain(node) {
  const parts = []; let curr = node;
  while (curr?.type === 'MemberExpression') { parts.unshift(curr.property.name || curr.property.value); curr = curr.object; }
  if (curr?.type === 'Identifier') parts.unshift(curr.name);
  return parts;
}

function getCalleeName(cal) {
  if (cal.type === 'Identifier') return cal.name;
  if (cal.type === 'MemberExpression') return getMemberChain(cal).join('.');
  return null;
}

function isCallTo(cal, pats) { const n = getCalleeName(cal); return n && pats.some(p => n === p || n.endsWith('.' + p)); }

function findFirstTaintedVar(node, tainted) {
    if (node.type === 'Identifier' && tainted.has(node.name)) return node.name;
    if (node.type === 'MemberExpression') return findFirstTaintedVar(node.object, tainted);
    return null;
}

function addFinding(findings, reported, info) {
  const key = `${info.type}|${info.sourceVar}|${info.sinkName}`;
  if (reported.has(key)) return;
  reported.add(key);
  findings.push({
    type: info.type, severity: 'critical', line: info.line, code_snippet: info.codeSnippet, description: info.description, fix: info.fix,
    confidence: computeConfidence(info.taintInfo, info.type), taint_path: info.taintInfo?.path || []
  });
}

const vScanner = new VulnerabilityScanner();
export function analyzeCode(code, language) {
  const lines = code.split('\n');
  return vScanner.scan(code, lines);
}
