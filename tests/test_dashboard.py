import importlib.util
import unittest

flask_available = importlib.util.find_spec("flask") is not None

if flask_available:
    from scripts.dashboard import suggest_grammar_from_crashes, summarize_crash_features


@unittest.skipUnless(flask_available, "flask not available")
class DashboardAnalysisTestCase(unittest.TestCase):
    def test_summarize_crash_features(self) -> None:
        summaries = [
            {"bounds_checks": 2, "type_checks": 1},
            {"bounds_checks": 3, "type_checks": 4, "deopt_points": 2},
        ]
        totals = summarize_crash_features(summaries)
        self.assertEqual(totals["bounds_checks"], 5)
        self.assertEqual(totals["type_checks"], 5)
        self.assertEqual(totals["deopt_points"], 2)

    def test_suggest_grammar_from_crashes(self) -> None:
        totals = {"bounds_checks": 30, "type_checks": 0, "deopt_points": 0}
        suggestions = suggest_grammar_from_crashes(totals)
        self.assertIn("length", suggestions)


if __name__ == "__main__":
    unittest.main()
