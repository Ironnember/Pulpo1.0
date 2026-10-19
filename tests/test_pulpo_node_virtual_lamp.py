import importlib.util
import sys
import tempfile
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
    def test_pulpo_node_virtual_lamp_canonical_kernel_checks(self):
        proof = load_proof()
        with tempfile.TemporaryDirectory(prefix="pulpo-node-virtual-lamp-test-") as workdir:
            result = proof.run_checks(Path(workdir))
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["checks_passed"], result["checks_total"])
        self.assertGreaterEqual(result["checks_total"], 14)
        self.assertEqual(result["event_count"], 1)
        self.assertIn("canonical kernel/state", result["boundary"])
        self.assertIn("No GPIO", result["boundary"])


if __name__ == "__main__":
    unittest.main()
