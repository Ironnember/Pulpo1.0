// Behavioral harness for public/app.js stale-response regression.
// Loads the real app.js with a stub DOM and a controllable fetch, then
// resolves scenario requests out of order. The trace and status must always
// belong to the most recently selected scenario.
// Usage: node tests/public_proof_lab_ui_harness.mjs [path/to/app.js]
// Exit code 0 and a PASS line on success; exit code 1 with FAIL lines otherwise.
import { readFileSync } from 'node:fs';

const appPath = process.argv[2] || 'public/app.js';
const src = readFileSync(appPath, 'utf8');

const trace = { textContent: '' };
const statusEl = { textContent: '' };

function makeButton(scenario) {
  return {
    dataset: { s: scenario },
    classList: { add() {}, remove() {} },
    _handler: null,
    addEventListener(_ev, fn) { this._handler = fn; },
    click() { return this._handler(); },
  };
}
const scenarios = ['safe_read', 'over_budget', 'unknown_action', 'needs_approval'];
const buttons = scenarios.map(makeButton);
const byScenario = Object.fromEntries(buttons.map((b) => [b.dataset.s, b]));

const documentStub = {
  querySelector(sel) {
    if (sel === '#trace') return trace;
    if (sel === '#status') return statusEl;
    throw new Error('unexpected selector ' + sel);
  },
  querySelectorAll(sel) {
    if (sel === '[data-s]') return buttons;
    throw new Error('unexpected selectorAll ' + sel);
  },
};

const pending = [];
function fetchStub(_url, opts) {
  const scenario = JSON.parse(opts.body).scenario;
  return new Promise((resolve, reject) => {
    pending.push({ scenario, resolve, reject });
  });
}
function payload(scenario, outcome) {
  return {
    permit_issued: false,
    permit_replay_rejected: null,
    intent: { principal: 'public-visitor', action: 'scenario', resource: scenario, cost: 0 },
    decision: { outcome, reason: 'REASON_' + scenario },
    audit_valid: true,
    boundary: 'BOUNDARY',
  };
}
function takePending(scenario) {
  const i = pending.findIndex((p) => p.scenario === scenario);
  if (i < 0) throw new Error('no pending request for ' + scenario);
  return pending.splice(i, 1)[0];
}
function respond(scenario, outcome) {
  takePending(scenario).resolve({ ok: true, json: async () => payload(scenario, outcome) });
}
function fail(scenario, message) {
  takePending(scenario).reject(new Error(message));
}

const failures = [];
function check(name, cond) {
  if (!cond) failures.push(name);
}

new Function('document', 'fetch', src)(documentStub, fetchStub);

// Race 1: slow first request resolves after the newer one.
const pA = byScenario['safe_read'].click();
const pB = byScenario['over_budget'].click();
respond('over_budget', 'deny');
await pB;
check('latest response renders', trace.textContent.includes('REASON_over_budget'));
check('latest status renders', statusEl.textContent === 'DENY / PROVED');
respond('safe_read', 'allow');
await pA;
check('stale response does not overwrite trace', trace.textContent.includes('REASON_over_budget') && !trace.textContent.includes('REASON_safe_read'));
check('stale response does not overwrite status', statusEl.textContent === 'DENY / PROVED');

// Race 2: a stale request fails after a newer selection; its failure must not
// replace the newer request's in-progress state.
const pC = byScenario['unknown_action'].click();
const pD = byScenario['needs_approval'].click();
fail('unknown_action', 'stale_failure');
await pC;
check('stale failure does not render FAILED CLOSED', statusEl.textContent === 'EVALUATING');
respond('needs_approval', 'require_approval');
await pD;
check('newer response renders after stale failure', trace.textContent.includes('REASON_needs_approval'));
check('newer status renders after stale failure', statusEl.textContent === 'STOP / APPROVAL REQUIRED');

if (failures.length) {
  for (const f of failures) console.log('FAIL: ' + f);
  process.exit(1);
}
console.log('PASS: stale scenario responses are ignored (success and failure paths)');
