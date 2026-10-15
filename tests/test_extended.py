import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from auditor import audit
from reporting import render_html


class ExtendedTests(unittest.TestCase):
    def rules(self,headers):
        return {f['rule'] for f in audit(headers)['findings']}

    def test_csp_first_directive_wins(self):
        self.assertIn('CSP_INLINE_REVIEW',self.rules([('Content-Security-Policy',"script-src 'unsafe-inline'; script-src 'none'")]))
        self.assertNotIn('CSP_INLINE_REVIEW',self.rules([('Content-Security-Policy',"script-src 'none'; script-src 'unsafe-inline'")]))

    def test_csp_eval_and_duplicate(self):
        rules=self.rules([('Content-Security-Policy',"default-src 'unsafe-eval'; default-src 'none'")])
        self.assertTrue({'CSP_EVAL_REVIEW','CSP_DUPLICATE_DIRECTIVE'}<=rules)

    def test_cors_wildcard_credentials(self):
        self.assertIn('CORS_WILDCARD_CREDENTIALS',self.rules([('Access-Control-Allow-Origin','*'),('Access-Control-Allow-Credentials','true')]))
        self.assertNotIn('CORS_WILDCARD_CREDENTIALS',self.rules([('Access-Control-Allow-Origin','*')]))

    def test_cors_null_duplicate_case_sensitive_credentials(self):
        rules=self.rules([('Access-Control-Allow-Origin','null'),('Access-Control-Allow-Origin','*'),('Access-Control-Allow-Credentials','True')])
        self.assertTrue({'CORS_NULL_ORIGIN','CORS_DUPLICATE_HEADER','CORS_CREDENTIALS_INVALID'}<=rules)

    def test_cookie_host_prefix(self):
        rules=self.rules([('Set-Cookie','__Host-session=SECRET; Domain=example.test; Path=/sub')])
        self.assertTrue({'COOKIE_PREFIX_HOST','COOKIE_PREFIX_SECURE'}<=rules)
        good=self.rules([('Set-Cookie','__Host-session=SECRET; Secure; HttpOnly; Path=/')])
        self.assertFalse({'COOKIE_PREFIX_HOST','COOKIE_PREFIX_SECURE'}&good)

    def test_http_cookie_prefix(self):
        self.assertIn('COOKIE_PREFIX_HTTPONLY',self.rules([('Set-Cookie','__Host-Http-id=secret; Secure; Path=/')]))

    def test_cookie_duplicates_and_samesite(self):
        rules=self.rules([('Set-Cookie','id=secret; Path=/; path=/x; SameSite=wrong')])
        self.assertTrue({'COOKIE_DUPLICATE_ATTRIBUTE','COOKIE_SAMESITE_INVALID'}<=rules)

    def test_input_validation(self):
        for headers in (None,{},['invalid'],[(1,'x')],[('x',None)]):
            with self.assertRaises(ValueError): audit(headers)
        with self.assertRaises(ValueError): audit([],scheme='ftp')

    def test_html_escapes_untrusted_names_and_omits_cookie_value(self):
        report=audit([('Set-Cookie','<script>alert(1)</script>=TOPSECRET')])
        html=render_html(report)
        self.assertNotIn('<script>',html)
        self.assertIn('&lt;script&gt;',html)
        self.assertNotIn('TOPSECRET',html)
        self.assertEqual(sum(report['summary'].values()),len(report['findings']))

    def test_cli_outputs_and_exit_codes(self):
        script=Path(__file__).resolve().parents[1]/'auditor.py'
        with tempfile.TemporaryDirectory() as directory:
            fixture=Path(directory)/'input.json'; target=Path(directory)/'report.html'
            fixture.write_text(json.dumps({'headers':[]}))
            def run(*args):
                return subprocess.run([sys.executable,str(script),'--fixture',str(fixture),*args],capture_output=True,text=True)
            self.assertEqual(run().returncode,0)
            alert=run('--fail-on-review')
            self.assertEqual(alert.returncode,1)
            self.assertGreater(json.loads(alert.stdout)['summary']['review'],0)
            self.assertEqual(run('--format','html','--output',str(target)).returncode,0)
            original=target.read_text()
            self.assertIn('<!doctype html>',original)
            self.assertEqual(run('--output',str(target)).returncode,2)
            self.assertEqual(target.read_text(),original)
            fixture.write_text('[]')
            result=run()
            self.assertEqual(result.returncode,2)
            self.assertNotIn('Traceback',result.stderr)
