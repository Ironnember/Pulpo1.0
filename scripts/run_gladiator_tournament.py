"""External bounded tournament over canonical Pulpo; no enforcement/admission gate."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import platform
import re
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time
import unittest

p = argparse.ArgumentParser()
p.add_argument('--repo', required=True)
p.add_argument('--output', required=True)
p.add_argument('--expected-revision', required=True)
a = p.parse_args()
repo = Path(a.repo).resolve()
out = Path(a.output).resolve()
if out == repo or repo in out.parents:
    raise SystemExit('Evidence output must be outside the source checkout')
if not re.fullmatch(r'[0-9a-f]{40}', a.expected_revision):
    raise SystemExit('Expected revision must be a full lowercase Git SHA')
out.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(repo))
from pulpo import Intent, SQLiteKernelState
from pulpo.directives import GovernedDirectiveProjection
from tests.test_directives import DirectiveProofTests, directive, derived, OPERATOR
from tests.test_constitutional_sequences import ConstitutionalSequenceTests

def git(*args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()

if git('status', '--porcelain'):
    raise SystemExit('Requires clean canonical source')
revision = git('rev-parse', 'HEAD')
if revision != a.expected_revision:
    raise SystemExit('Source revision differs from the requested proof object')
paths = git('ls-files', 'pulpo', 'tests', 'AGENTS.md', '.agents/skills/prove-pulpo35', 'docs/PULPO35_CHAT_CONTRACT.md', 'scripts/run_gladiator_tournament.py').splitlines()
hashes = {s: hashlib.sha256((repo / s).read_bytes()).hexdigest() for s in paths if (repo / s).is_file()}
rows = []

class DetailedResult(unittest.TextTestResult):
    def startTest(self, test):
        super().startTest(test)
        self.case_rows.append({'test': test.id(), 'outcome': 'RUNNING'})
    def addSuccess(self, test):
        super().addSuccess(test)
        self.case_rows[-1]['outcome'] = 'PASS'
    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.case_rows[-1]['outcome'] = 'FAILURE_REQUIRES_TRIAGE'
    def addError(self, test, err):
        super().addError(test, err)
        self.case_rows[-1]['outcome'] = 'BLOCKED_OR_ERROR_REQUIRES_TRIAGE'
    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.case_rows[-1].update(outcome='UNTESTED', reason=reason)
    def __init__(self, *args):
        super().__init__(*args)
        self.case_rows = []

def run(label, suite, **meta):
    stream = io.StringIO()
    start = time.monotonic()
    with redirect_stdout(stream), redirect_stderr(stream):
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=DetailedResult).run(suite)
    (out / (label + '.log')).write_text(stream.getvalue())
    row = dict(label=label, tests=result.testsRun, failures=len(result.failures),
               errors=len(result.errors), skips=len(result.skipped),
               seconds=round(time.monotonic() - start, 3), cases=result.case_rows, **meta)
    rows.append(row)
    print(json.dumps({k: v for k, v in row.items() if k != 'cases'}), flush=True)
    return result.wasSuccessful() and not result.skipped

class ComposedAuthorityChain(DirectiveProofTests):
    SEED = 1
    def test_composed_denials_control_revocation_and_restart(self):
        rng = random.Random(self.SEED)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'chain.sqlite3'
            state = SQLiteKernelState(path)
            try:
                parent = directive(directive_id=f'parent-{self.SEED}')
                kernel, verifier, controller = self.activate(state, parent)
                child = derived(parent, directive_id=f'child-{self.SEED}')
                self.activate_child(kernel, verifier, controller, parent, child)
                intent = Intent('agent:builder', 'write', f'repo:service:{rng.randrange(100000)}', 1)
                target = kernel.lock_target('chain-target', intent)
                projection = GovernedDirectiveProjection(kernel)
                decision = projection.evaluate(intent, child)
                self.assertEqual('allow', decision.outcome)
                self.assertIsNotNone(decision.permit)
                attacks = ['budget', 'principal', 'resource', 'directive_bytes', 'target_hash', 'permit_object']
                rng.shuffle(attacks)
                self.ATTACK_ORDER = attacks
                for index, attack in enumerate(attacks):
                    if index == 3:
                        state.close()
                        state = SQLiteKernelState(path)
                        kernel, verifier = self.governed(state)
                        projection = GovernedDirectiveProjection(kernel)
                        self.assertTrue(kernel.verify_audit())
                    if attack == 'target_hash':
                        observed = kernel.resolve_locked_target(target.target_id, '0' * 64)
                        self.assertEqual(('deny', 'target_hash_mismatch'), (observed.outcome, observed.reason))
                    elif attack == 'permit_object':
                        self.assertFalse(kernel.consume(decision.permit, replace(intent, resource='repo:substituted')))
                    else:
                        bad_intent, bad_directive = intent, child
                        if attack == 'budget': bad_intent = replace(intent, cost=child.max_cost + 1)
                        if attack == 'principal': bad_intent = replace(intent, principal='agent:impostor')
                        if attack == 'resource': bad_intent = replace(intent, resource='shell:root')
                        if attack == 'directive_bytes': bad_directive = replace(child, max_cost=99)
                        rejected = projection.evaluate(bad_intent, bad_directive)
                        self.assertEqual('deny', rejected.outcome)
                        self.assertIsNone(rejected.permit)
                # Six denials, including a mid-chain restart, must preserve the valid control.
                self.assertTrue(kernel.consume(decision.permit, intent))
                self.assertFalse(kernel.consume(decision.permit, intent))
                later = projection.evaluate(intent, child)
                self.assertEqual('allow', later.outcome)
                from pulpo.directives import DirectiveAuthorityController
                controller = DirectiveAuthorityController(kernel)
                envelope = self.approve(kernel, verifier, controller.REVOKE, parent, 'revoke-chain', 'revoke-chain-nonce')
                self.assertEqual('allow', controller.revoke(parent, envelope, operator_principal=OPERATOR).outcome)
                state.close()
                state = SQLiteKernelState(path)
                kernel, _ = self.governed(state)
                self.assertFalse(kernel.consume(later.permit, intent))
                self.assertEqual('directive_parent_revoked', GovernedDirectiveProjection(kernel).evaluate(intent, child).reason)
                self.assertTrue(kernel.verify_audit())
            finally:
                state.close()

teams = {
    'authority': ['tests.test_authority', 'tests.test_directives'],
    'consequence': ['tests.test_execution_context_binding', 'tests.test_custody_executor', 'tests.test_custody_domain', 'tests.test_commerce'],
    'state': ['tests.test_persistence', 'tests.test_custody'],
    'evidence': ['tests.test_issue_153_consequence_reconciliation_v0', 'tests.test_mcp_boundary'],
}
okay = True
for team, names in teams.items():
    okay = run('qualification-' + team, unittest.defaultTestLoader.loadTestsFromNames(names), phase='qualification', team=team) and okay

for wave, steps in enumerate((500, 750, 1000, 1250), 1):
    for round_no in (1, 2):
        seed = 0x351000 + wave * 100 + round_no
        cls = type(f'MixedW{wave}R{round_no}', (ConstitutionalSequenceTests,), {'SEED': seed, 'STEPS': steps})
        okay = run(f'mixed-w{wave}-r{round_no}', unittest.defaultTestLoader.loadTestsFromTestCase(cls), phase='mixed', seed=seed, scheduled_steps=steps) and okay

for phase, seeds in [('composition', (35101, 35102, 35103, 35104)), ('held-out', (35991, 35992, 35993, 35994))]:
    for seed in seeds:
        cls = type(f'Chain{seed}', (ComposedAuthorityChain,), {'SEED': seed})
        case = cls('test_composed_denials_control_revocation_and_restart')
        okay = run(f'{phase}-chain-{seed}', unittest.TestSuite([case]), phase=phase, seed=seed, shared_state_within_round=True) and okay
        rows[-1]['attack_order'] = getattr(case, 'ATTACK_ORDER', [])

for seed in (0x35FF01, 0x35FF02, 0x35FF03, 0x35FF04):
    cls = type(f'HeldOut{seed}', (ConstitutionalSequenceTests,), {'SEED': seed, 'STEPS': 900})
    okay = run(f'held-out-mixed-{seed}', unittest.defaultTestLoader.loadTestsFromTestCase(cls), phase='held-out', seed=seed, scheduled_steps=900) and okay

after_hashes = {s: hashlib.sha256((repo / s).read_bytes()).hexdigest() for s in hashes}
report = {'schema': 'pulpo35.bounded-tournament.v1', 'revision': revision, 'rows': rows,
          'python': sys.version, 'platform': platform.platform(),
          'total_test_executions': sum(r['tests'] for r in rows),
          'planned_mixed_operations': sum(r.get('scheduled_steps', 0) for r in rows),
          'scheduled_mixed_operations': sum(r.get('scheduled_steps', 0) for r in rows if not (r['failures'] or r['errors'] or r['skips'])),
          'source_unchanged': hashes == after_hashes, 'clean_tree_after': not git('status', '--porcelain'),
          'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'source_hashes': hashes,
          'boundary': 'Synthetic local software tournament, four teams as test groupings. Fresh fixtures between rounds. No autonomous attacker agents, independent reviewer, SENTRY, deployed ingress, OS containment, external provider, or full 24-condition fleet tournament.'}
okay = okay and report['source_unchanged'] and report['clean_tree_after']
report['result'] = 'PASS_WITH_BOUNDARIES' if okay else 'HOLD_FOR_TRIAGE'
(out / 'tournament-results.json').write_text(json.dumps(report, indent=2) + '\n')
print('FINAL', report['result'], report['total_test_executions'], report['scheduled_mixed_operations'], flush=True)
raise SystemExit(0 if okay else 1)
