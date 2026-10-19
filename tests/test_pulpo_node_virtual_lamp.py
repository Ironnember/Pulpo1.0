import importlib.util
import sys
import unittest
from pathlib import Path


def load_proof():
    path = Path(__file__).resolve().parents[1] / "proofs" / "pulpo-node" / "virtual_lamp_proof.py"
    spec = importlib.util.spec_from_file_location("pulpo_node_virtual_lamp", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PulpoNodeVirtualLampTests(unittest.TestCase):
    def test_pulpo_node_virtual_lamp_13_checks(self):
        proof = load_proof()
        result = proof.run_checks(Path(self._testMethodName))
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["checks_passed"], 13)
        self.assertEqual(result["checks_total"], 13)
        self.assertEqual(result["event_count"], 1)
        self.assertIn("No GPIO", result["boundary"])


if __name__ == "__main__":
    unittest.main()
