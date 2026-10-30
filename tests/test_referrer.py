import unittest
from auditor import audit


class ReferrerTests(unittest.TestCase):
    def rules(self, values):
        return {f['rule'] for f in audit([('Referrer-Policy', v) for v in values])['findings']}

    def test_empty_and_unknown_invalid(self):
        for value in ('', 'invalid', ' , unknown, '):
            self.assertIn('REFERRER_POLICY_INVALID',self.rules([value]))

    def test_last_recognized_token_wins(self):
        self.assertNotIn('REFERRER_POLICY_UNSAFE_URL',self.rules(['unsafe-url, no-referrer']))
        self.assertIn('REFERRER_POLICY_UNSAFE_URL',self.rules(['no-referrer, unsafe-url']))

    def test_unknown_fallback_ignored(self):
        self.assertNotIn('REFERRER_POLICY_INVALID',self.rules(['unknown, strict-origin']))
        self.assertIn('REFERRER_POLICY_UNSAFE_URL',self.rules(['unsafe-url, unknown']))

    def test_multiple_header_order(self):
        self.assertIn('REFERRER_POLICY_UNSAFE_URL',self.rules(['no-referrer','unsafe-url']))

    def test_missing_remains_informational(self):
        self.assertIn('REFERRER_POLICY_MISSING',self.rules([]))
