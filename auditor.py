"""Single-response HTTP header linting; no crawler or vulnerability verdict."""
import argparse
from email.message import Message
import http.client
import json
from pathlib import Path
from urllib.parse import urlsplit


def audit(headers, scheme='https'):
    h = {}
    for name, value in headers:
        h.setdefault(name.lower(), []).append(value.strip())
    findings = []
    def add(rule, level, detail):
        findings.append(dict(rule=rule, severity=level, detail=detail))
    for name in ('strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options'):
        if len(h.get(name, [])) > 1:
            add('DUPLICATE_HEADER', 'review', name + ': duplicate values require manual browser-semantics review')
    csp = h.get('content-security-policy', [''])[0]
    directives = {part.strip().split()[0].lower():part.strip().split()[1:]
                  for part in csp.split(';') if part.strip()}
    if not csp:
        add('CSP_MISSING', 'review', 'No enforcing CSP; report-only policies do not enforce restrictions.')
    elif "'unsafe-inline'" in directives.get('script-src', directives.get('default-src', [])):
        add('CSP_INLINE_REVIEW', 'review', 'Inline script allowance present; nonce/hash/strict-dynamic context requires manual review.')
    frame = h.get('x-frame-options', [''])[0].upper()
    if 'frame-ancestors' not in directives and frame not in ('DENY','SAMEORIGIN'):
        add('FRAMING_POLICY_MISSING', 'review', 'No recognized frame-ancestors or X-Frame-Options protection.')
    if h.get('x-content-type-options', [''])[0].lower() != 'nosniff':
        add('NOSNIFF_MISSING', 'review', 'X-Content-Type-Options should be reviewed for nosniff.')
    if scheme == 'https':
        policy = h.get('strict-transport-security', [''])[0]
        values = [p.strip().split('=',1) for p in policy.split(';')]
        ages = [p[1] for p in values if len(p)==2 and p[0].lower()=='max-age']
        if len(ages)!=1 or not ages[0].isdigit() or int(ages[0])<=0:
            add('HSTS_INACTIVE', 'review', 'Missing, ambiguous, invalid or zero HSTS max-age.')
    else:
        add('CLEARTEXT_HTTP', 'review', 'HTTP response; HSTS on this response would not establish HTTPS protection.')
    if not h.get('referrer-policy'):
        add('REFERRER_POLICY_MISSING','info','No explicit Referrer-Policy; browser defaults still apply.')
    for cookie in h.get('set-cookie', []):
        parts = [x.strip() for x in cookie.split(';')]
        name = parts[0].split('=',1)[0]
        attrs = {x.split('=',1)[0].lower(): x.split('=',1)[1] if '=' in x else '' for x in parts[1:]}
        # Cookie values are never copied to reports.
        if 'secure' not in attrs:
            add('COOKIE_SECURE_REVIEW','review',name + ': Secure flag absent')
        if 'httponly' not in attrs:
            add('COOKIE_HTTPONLY_REVIEW','review',name + ': HttpOnly absent; assess whether JavaScript needs this cookie')
        if attrs.get('samesite','').lower()=='none' and 'secure' not in attrs:
            add('COOKIE_SAMESITE_NONE','review',name + ': SameSite=None without Secure')
    return dict(scope='single response; heuristic lint, not a security grade', findings=findings)


def fetch(url):
    p=urlsplit(url)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.query or p.fragment:
        raise ValueError('Use http(s) URL without credentials, query or fragment.')
    cls=http.client.HTTPSConnection if p.scheme=='https' else http.client.HTTPConnection
    connection=cls(p.hostname,p.port,timeout=10)
    try:
        connection.request('HEAD',p.path or '/',headers={'User-Agent':'HeaderAuditor/1.0'})
        response=connection.getresponse()
        return response.status,response.getheaders(),p.scheme
    finally:
        connection.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--fixture',type=Path,help='JSON: scheme and headers as name/value pairs')
    group.add_argument('--url',help='One HEAD request to an authorized URL; redirects are not followed')
    args=parser.parse_args()
    try:
        if args.fixture:
            data=json.loads(args.fixture.read_text()); status=data.get('status',200)
            report=audit(data['headers'],data.get('scheme','https'))
        else:
            status,headers,scheme=fetch(args.url); report=audit(headers,scheme)
        report['status']=status
        print(json.dumps(report,indent=2))
    except (OSError,ValueError,KeyError,http.client.HTTPException) as exc:
        parser.exit(2, f'Cannot audit response: {exc}\n')

if __name__=='__main__': main()
