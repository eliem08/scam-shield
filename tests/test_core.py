import unittest

from scam_shield import analyze, hash_safeword, lookalike, verify_safeword


class Tests(unittest.TestCase):
    def test_grandparent_scam(self):
        v = analyze("Grandma it's me, I'm in jail. Please don't tell mom. I need bail money in Apple gift cards right away.")
        self.assertEqual(v.label, "likely scam")
        names = {s.name for s in v.signals}
        self.assertTrue({"family_emergency", "secrecy", "gift_cards", "urgency"} <= names)
        self.assertTrue(any("safe word" in a for a in v.advice))

    def test_benign(self):
        v = analyze("Hi mom, dinner Sunday at 6? I'll bring dessert.")
        self.assertEqual(v.label, "safe")

    def test_lookalike(self):
        self.assertEqual(lookalike("paypa1.com"), "paypal")
        self.assertEqual(lookalike("arnazon.com"), "amazon")
        self.assertEqual(lookalike("paypal-security.net"), "paypal")
        self.assertIsNone(lookalike("paypal.com"))
        self.assertIsNone(lookalike("example.org"))
        self.assertEqual(lookalike("xn--pypal-4ve.com"), "punycode")

    def test_phishing_email(self):
        v = analyze("Suspicious activity on your account. Verify your account: [paypal.com](http://198.51.100.7/login)",
                    sender="security@paypa1.com")
        names = {s.name for s in v.signals}
        self.assertTrue({"lookalike_domain", "link_mismatch", "raw_ip_link", "credential_request"} <= names)
        self.assertEqual(v.score, 100)

    def test_safeword(self):
        h = hash_safeword("Purple Pancakes")
        self.assertTrue(verify_safeword("purple pancakes ", h))
        self.assertFalse(verify_safeword("blue waffles", h))


if __name__ == "__main__":
    unittest.main()
