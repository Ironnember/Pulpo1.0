"""Probe acceptance checks must never disappear under Python optimization."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


class OllamaProofPreconditionTests(unittest.TestCase):
    def test_both_probes_refuse_optimization_before_inference_or_worker_start(self):
        root = Path(__file__).resolve().parents[1]
        for module in ("probe_ollama_proposal", "probe_ollama_worker_isolation"):
            for flag in ("-O", "-OO"):
                with self.subTest(module=module, flag=flag):
                    code = f"from scripts import {module} as p\n"
                    code += "p.request_local_proposal=lambda *a: (_ for _ in ()).throw(RuntimeError('INFERENCE_REACHED'))\n"
                    code += "p.main()\n"
                    result = subprocess.run([sys.executable, flag, "-c", code], cwd=root,
                                            capture_output=True, text=True, timeout=10)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("proof_requires_assertions_enabled", result.stderr)
                    self.assertNotIn("INFERENCE_REACHED", result.stderr)

    def test_environment_optimization_also_refused_before_side_effects(self):
        root = Path(__file__).resolve().parents[1]
        for module in ("probe_ollama_proposal", "probe_ollama_worker_isolation"):
            with self.subTest(module=module):
                result = subprocess.run([sys.executable, "-m", "scripts." + module, "--help"],
                    cwd=root, env=dict(os.environ, PYTHONOPTIMIZE="1"),
                    capture_output=True, text=True, timeout=10)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("proof_requires_assertions_enabled", result.stderr)

    def test_normal_mode_rejects_wrong_model_action_without_network(self):
        import contextlib
        import io
        from unittest.mock import patch
        from scripts import probe_ollama_proposal as probe
        with patch.object(sys, "argv", ["probe", "--model", "synthetic:tag", "--digest", "f" * 64]), \
             patch.object(probe, "request_local_proposal", return_value=
                          '{"action":"read","resource":"repo:synthetic-demo","cost":0}'), \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaises(AssertionError):
            probe.main()


if __name__ == "__main__":
    unittest.main(verbosity=2)
