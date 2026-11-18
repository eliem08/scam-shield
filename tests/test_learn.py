import contextlib
import csv
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from scam_shield.__main__ import main
from scam_shield.core import analyze
from scam_shield.learn import Model, evaluate, load_labelled, model_path, tokens
from tests.synth import make_messages


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(list(argv))
    return code, out.getvalue()


class LearnTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"SCAM_SHIELD_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def trained(self) -> Model:
        m = Model()
        for text, label in make_messages():
            m.add(text, label)
        return m

    def test_learning_catches_what_the_rules_miss(self):
        msg = "Unpaid toll balance of $6.99 on your vehicle. Pay at toll-pay-center.net to avoid a late fee."
        self.assertEqual(analyze(msg).label, "safe")  # no rule keyword in it
        v = analyze(msg, model=self.trained())
        self.assertNotEqual(v.label, "safe")
        self.assertEqual(v.signals[0].name, "learned_pattern")

    def test_learning_never_removes_a_rule_warning(self):
        m = Model()
        warn = "Grandma it's me, I'm in jail, send bail money in gift cards, don't tell mom"
        for _ in range(20):  # someone marks this exact scam as safe, over and over
            m.add(warn, "safe")
            m.add("Unpaid toll, pay now at toll-pay-center.net", "scam")
        self.assertEqual(analyze(warn, model=m).label, "likely scam")

    def test_untrained_model_does_nothing_and_counts_not_messages_are_stored(self):
        m = Model()
        for text, label in make_messages(12):
            m.add(text, label)
        self.assertFalse(m.ready)
        self.assertEqual(analyze("Unpaid toll at toll-pay-center.net", model=m).signals, [])
        self.trained().save()
        saved = model_path().read_text(encoding="utf-8")
        self.assertNotIn("could not be delivered", saved)  # word counts only
        self.assertTrue(Model.load().ready)

    def test_cross_validated_evaluation(self):
        ev = evaluate(make_messages())
        self.assertGreater(ev["rules_and_learning"]["detection"], ev["rules"]["detection"])
        self.assertLessEqual(ev["rules_and_learning"]["false_alarms"], 0.1)

    def test_tokens_normalise_links_money_and_numbers(self):
        toks = tokens("Pay $6.99 at https://evil.example/x now, code 1234")
        self.assertIn("_money_", toks)
        self.assertIn("_url_", toks)
        self.assertIn("_num_", toks)
        self.assertIn("pay _money_", toks)

    def test_labelled_csv(self):
        path = os.path.join(self.tmp.name, "l.csv")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            csv.writer(fh).writerows([["message", "class"], ["win a car", "spam"], ["hi mum", "ham"]])
        self.assertEqual(load_labelled(path), [("win a car", "scam"), ("hi mum", "safe")])
        with open(path, "w", encoding="utf-8", newline="") as fh:
            csv.writer(fh).writerows([["text", "label"], ["x", "maybe"]])
        with self.assertRaisesRegex(ValueError, "line 2"):
            load_labelled(path)
        with self.assertRaises(ValueError):
            Model().add("  ", "scam")

    def test_cli_report_learn_and_check(self):
        code, out = run("report", "Your parcel is held, pay the fee at parcel-fee.com", "--scam")
        self.assertEqual(code, 0)
        self.assertIn("learning starts after", out)
        path = os.path.join(self.tmp.name, "r.csv")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["text", "label"])
            w.writerows(make_messages())
        code, out = run("learn", path)
        self.assertEqual(code, 0, out)
        self.assertIn("rules + learning", out)
        _, out = run("check", "Hi, I am a recruiter. Remote job, earn $300 daily. Reply YES for details.")
        self.assertIn("learned_pattern", out)
        doc = json.loads(model_path().read_text(encoding="utf-8"))
        self.assertEqual(doc["docs"]["scam"], 1 + sum(lab == "scam" for _, lab in make_messages()))


if __name__ == "__main__":
    unittest.main()
