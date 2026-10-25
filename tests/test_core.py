import unittest

from scam_shield import analyze, hash_safeword, lookalike, verify_safeword


class Tests(unittest.TestCase):
    def test_grandparent_scam(self):
        v = analyze(
            "Grandma it's me, I'm in jail. Please don't tell mom. I need bail money in Apple gift cards right away."
        )
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
        v = analyze(
            "Suspicious activity on your account. Verify your account: [paypal.com](http://198.51.100.7/login)",
            sender="security@paypa1.com",
        )
        names = {s.name for s in v.signals}
        self.assertTrue({"lookalike_domain", "link_mismatch", "raw_ip_link", "credential_request"} <= names)
        self.assertEqual(v.score, 100)

    def test_safeword(self):
        h = hash_safeword("Purple Pancakes")
        self.assertTrue(verify_safeword("purple pancakes ", h))
        self.assertFalse(verify_safeword("blue waffles", h))

    def test_cheap_text_evasions_are_undone(self):
        smart_quotes = "Grandma it\u2019s me, I\u2019m in jail. Don\u2019t tell mom."
        self.assertEqual({s.name for s in analyze(smart_quotes).signals}, {"family_emergency", "secrecy"})
        for text in (
            "buy gift\u200bcards now",
            "\uff47\uff49\uff46\uff54 \uff43\uff41\uff52\uff44\uff53",
            "GIFT\u00adCARDS",
        ):
            with self.subTest(text=text.encode("unicode_escape")):
                self.assertIn("gift_cards", {s.name for s in analyze(text).signals})

    def test_brand_hidden_in_subdomain_or_country_suffix(self):
        self.assertEqual(lookalike("paypal.com.secure-login.ru"), "paypal")
        self.assertEqual(lookalike("amaz0n.co.uk"), "amazon")
        self.assertEqual(lookalike("\u0430pple.com"), "punycode")  # Cyrillic a, not encoded
        for real in ("amazon.co.uk", "support.apple.com", "mail.google.com", "paypal.com"):
            with self.subTest(real=real):
                self.assertIsNone(lookalike(real))

    def test_link_mismatch_is_not_fooled_by_a_suffix_match(self):
        names = {s.name for s in analyze("[paypal.com](https://evilpaypal.com/login)").signals}
        self.assertIn("link_mismatch", names)
        self.assertEqual(analyze("[paypal.com](https://www.paypal.com/help)").signals, [])


if __name__ == "__main__":
    unittest.main()
