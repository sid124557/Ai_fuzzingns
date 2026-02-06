import unittest

from scripts.fuzzing.signals import (
    compute_deviation_score,
    detect_coverage,
    detect_patterns,
    parse_maglev_output,
)


class SignalsTestCase(unittest.TestCase):
    def test_parse_maglev_output(self) -> None:
        output = "CheckMaps\nCheckBounds\nInlined\nDeopt\nDeopt"
        stats = parse_maglev_output(output)
        self.assertEqual(stats["checkmaps"], 1)
        self.assertEqual(stats["checkbounds"], 1)
        self.assertEqual(stats["inlining"], 1)
        self.assertEqual(stats["deopts"], 2)

    def test_detect_patterns(self) -> None:
        output = "lazy eager Inlined elements transition Allocate CheckBounds"
        patterns = detect_patterns(output)
        self.assertGreaterEqual(patterns["deopt_lazy"], 1)
        self.assertGreaterEqual(patterns["deopt_eager"], 1)
        self.assertGreaterEqual(patterns["inline"], 1)
        self.assertGreaterEqual(patterns["elements_transition"], 1)
        self.assertGreaterEqual(patterns["allocation"], 1)
        self.assertGreaterEqual(patterns["bounds"], 1)

    def test_detect_coverage(self) -> None:
        output = "Block b1\nBlock b2\nCheckMaps\nLoadField\nStoreField\nCallJS"
        coverage = detect_coverage(output)
        self.assertEqual(coverage["blocks"], 2)
        self.assertEqual(coverage["ops"], 4)

    def test_compute_deviation_score(self) -> None:
        baseline = {"checkmaps": 2.0, "ops": 5.0}
        current = {"checkmaps": 4, "ops": 1}
        score = compute_deviation_score(current, baseline)
        self.assertEqual(score, 6.0)


if __name__ == "__main__":
    unittest.main()
