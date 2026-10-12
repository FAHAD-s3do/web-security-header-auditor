import unittest
import auditor as a
class Tests(unittest.TestCase):
 def rules(self,h,scheme='https'):return {f['rule'] for f in a.audit(h,scheme)['findings']}
 def test_valid_headers(self):
  h=[('Content-Security-Policy',"default-src 'self'; frame-ancestors 'none'"),('Strict-Transport-Security','max-age=31536000'),('X-Content-Type-Options','nosniff'),('Referrer-Policy','no-referrer')]
  self.assertEqual(a.audit(h)['findings'],[])
 def test_report_only_not_enforced(self):self.assertIn('CSP_MISSING',self.rules([('Content-Security-Policy-Report-Only',"default-src 'none'")]))
 def test_cookie_values_redacted(self):
  report=a.audit([('Set-Cookie','session=TOPSECRET; SameSite=None')])
  self.assertNotIn('TOPSECRET',str(report));self.assertIn('COOKIE_SAMESITE_NONE',{f['rule'] for f in report['findings']})
 def test_hsts_zero(self):self.assertIn('HSTS_INACTIVE',self.rules([('Strict-Transport-Security','max-age=0')]))
 def test_http_not_hsts(self):self.assertNotIn('HSTS_INACTIVE',self.rules([], 'http'))
 def test_duplicates(self):self.assertIn('DUPLICATE_HEADER',self.rules([('X-Frame-Options','DENY'),('x-frame-options','SAMEORIGIN')]))
 def test_reject_credentials(self):
  with self.assertRaises(ValueError):a.fetch('https://user:password@example.test')
