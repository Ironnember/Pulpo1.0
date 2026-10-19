import unittest

from scripts.demo_orchestrator import main


class OrchestratorDemoTests(unittest.TestCase):
    def test_demo_exercises_must_fix_boundaries(self):
        main()


if __name__ == "__main__":
    unittest.main()
