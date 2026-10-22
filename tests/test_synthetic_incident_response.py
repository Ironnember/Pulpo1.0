import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


def load_proof():
    path = Path(__file__).resolve().parents[1] / "proofs" / "incident-response" / "synthetic_incident_response_proof.py"
    spec = importlib.util.spec_from_file_location("synthetic_incident_response_proof", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SyntheticIncidentResponseProofTests(unittest.TestCase):
    def test_synthetic_incident_response_checks(self):
        proof = load_proof()
        with tempfile.TemporaryDirectory(prefix="pulpo-synthetic-incident-response-test-") as workdir:
            result = proof.run_checks(Path(workdir))
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["checks_passed"], result["checks_total"])
        self.assertGreaterEqual(result["checks_total"], 14)
        self.assertEqual(result["remediation_count"], 1)
        self.assertIn("No real malware", result["boundary"])


if __name__ == "__main__":
    unittest.main()
