import unittest

from pulpo_authority_service.admission import AdmissionConfig, AdmissionController, AdmissionRejected


class AdmissionTests(unittest.TestCase):
    def test_rate_limit_is_bounded_and_retryable(self):
        now = [10.0]
        controller = AdmissionController(
            AdmissionConfig(requests_per_window=1, principal_budget=4),
            clock=lambda: now[0],
        )
        with controller.enter("worker:a"):
            pass
        with self.assertRaises(AdmissionRejected) as rejected:
            controller.enter("worker:a")
        self.assertGreaterEqual(rejected.exception.retry_after_seconds, 1)
        now[0] += 61
        with controller.enter("worker:a"):
            pass

    def test_poll_budget_is_separate_and_unknown_principal_fails_closed(self):
        controller = AdmissionController(AdmissionConfig(polls_per_window=1))
        with controller.enter("worker:a", poll=True):
            pass
        with self.assertRaises(AdmissionRejected):
            controller.enter("worker:a", poll=True)
        with self.assertRaises(AdmissionRejected):
            controller.enter(" ")


if __name__ == "__main__":
    unittest.main()
