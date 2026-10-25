import unittest
from auditor import audit


class CookieSpacingTests(unittest.TestCase):
    def rules(self, cookie):
        return {f['rule'] for f in audit([('Set-Cookie', cookie)])['findings']}

    def test_host_prefix_accepts_padded_path(self):
        self.assertNotIn('COOKIE_PREFIX_HOST', self.rules('__Host-id=value; Secure; HttpOnly; Path = /'))

    def test_padded_samesite_none_requires_secure(self):
        self.assertIn('COOKIE_SAMESITE_NONE', self.rules('id=value; SameSite = None'))

    def test_padded_invalid_samesite_is_reported(self):
        self.assertIn('COOKIE_SAMESITE_INVALID', self.rules('id=value; SameSite = invalid'))

    def test_padded_domain_still_breaks_host_prefix(self):
        self.assertIn('COOKIE_PREFIX_HOST', self.rules('__Host-id=value; Secure; Path=/; Domain = example.com'))

    def test_duplicate_detection_survives_spacing(self):
        self.assertIn('COOKIE_DUPLICATE_ATTRIBUTE', self.rules('id=value; Path=/; Path = /other'))
