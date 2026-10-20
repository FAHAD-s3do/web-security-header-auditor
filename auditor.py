"""Single-response HTTP header linting; no crawler or vulnerability verdict."""
import argparse
from reporting import render_html
import http.client
import json
from pathlib import Path
from urllib.parse import urlsplit


def audit(headers, scheme='https'):
    if scheme not in ('http','https'):
        raise ValueError('Scheme must be http or https')
    if not isinstance(headers, (list,tuple)):
        raise ValueError('Headers must be a list of name/value pairs')
    for pair in headers:
        if not isinstance(pair,(list,tuple)) or len(pair)!=2 or not all(isinstance(x,str) for x in pair):
            raise ValueError('Each header must contain two strings')
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
    directives = {}
    for part in csp.split(';'):
        tokens=part.split()
        if not tokens: continue
        directive=tokens[0].lower()
        if directive in directives:
            add('CSP_DUPLICATE_DIRECTIVE','review',directive + ': first occurrence retained; later duplicates ignored')
        else: directives[directive]=tokens[1:]
    if not csp:
        add('CSP_MISSING', 'review', 'No enforcing CSP; report-only policies do not enforce restrictions.')
    elif "'unsafe-inline'" in directives.get('script-src', directives.get('default-src', [])):
        add('CSP_INLINE_REVIEW', 'review', 'Inline script allowance present; nonce/hash/strict-dynamic context requires manual review.')
    if "'unsafe-eval'" in directives.get('script-src',directives.get('default-src',[])):
        add('CSP_EVAL_REVIEW','review','Dynamic string evaluation allowed; assess whether it is required.')
    frame = h.get('x-frame-options', [''])[0].upper()
    if 'frame-ancestors' not in directives and frame not in ('DENY','SAMEORIGIN'):
        add('FRAMING_POLICY_MISSING', 'review', 'No recognized frame-ancestors or X-Frame-Options protection.')
    if h.get('x-content-type-options', [''])[0].lower() != 'nosniff':
        add('NOSNIFF_MISSING', 'review', 'X-Content-Type-Options should be reviewed for nosniff.')
    if scheme == 'https':
        policy = h.get('strict-transport-security', [''])[0]
        values = [p.strip().split('=',1) for p in policy.split(';')]
        ages = [p[1] for p in values if len(p)==2 and p[0].lower()=='max-age']
        # HTTP delta-seconds use ASCII digits. Avoid int(): Unicode digit
        # characters and extremely long decimal strings can raise ValueError.
        if (len(ages)!=1 or not ages[0] or
                any(char not in '0123456789' for char in ages[0]) or
                not any(char != '0' for char in ages[0])):
            add('HSTS_INACTIVE', 'review', 'Missing, ambiguous, invalid or zero HSTS max-age.')
    else:
        add('CLEARTEXT_HTTP', 'review', 'HTTP response; HSTS on this response would not establish HTTPS protection.')
    if not h.get('referrer-policy'):
        add('REFERRER_POLICY_MISSING','info','No explicit Referrer-Policy; browser defaults still apply.')
    origins=h.get('access-control-allow-origin',[])
    credentials=h.get('access-control-allow-credentials',[])
    if len(origins)>1 or len(credentials)>1:
        add('CORS_DUPLICATE_HEADER','review','Multiple CORS origin/credentials headers need review; browser acceptance may fail.')
    if origins and origins[0]=='*' and 'true' in credentials:
        add('CORS_WILDCARD_CREDENTIALS','review','Wildcard origin cannot grant credentialed browser access; browsers block this combination, not leak credentials.')
    if origins and origins[0]=='null':
        add('CORS_NULL_ORIGIN','review','The null origin can represent multiple opaque origins; verify that this trust is intentional.')
    if credentials and any(v!='true' for v in credentials):
        add('CORS_CREDENTIALS_INVALID','review','Access-Control-Allow-Credentials only accepts the case-sensitive value true; omit it to disallow credentials.')
    for cookie in h.get('set-cookie', []):
        parts = [x.strip() for x in cookie.split(';')]
        name = parts[0].split('=',1)[0]
        attrs = {x.split('=',1)[0].lower(): x.split('=',1)[1] if '=' in x else '' for x in parts[1:]}
        keys=[x.split('=',1)[0].strip().lower() for x in parts[1:] if x]
        if len(keys)!=len(set(keys)):
            add('COOKIE_DUPLICATE_ATTRIBUTE','review',name + ': duplicate attributes require review')
        if name.startswith(('__Host-','__Secure-','__Http-')) and ('secure' not in attrs or scheme!='https'):
            add('COOKIE_PREFIX_SECURE','review',name + ': prefixed cookie requires Secure over HTTPS (local browser exceptions not modeled)')
        if name.startswith('__Host-') and ('domain' in attrs or attrs.get('path')!='/'):
            add('COOKIE_PREFIX_HOST','review',name + ': host prefix requires Path=/ and no Domain attribute')
        if name.startswith(('__Http-','__Host-Http-')) and 'httponly' not in attrs:
            add('COOKIE_PREFIX_HTTPONLY','review',name + ': HTTP prefix requires HttpOnly in supporting browsers')
        if attrs.get('samesite','').lower() not in ('','strict','lax','none'):
            add('COOKIE_SAMESITE_INVALID','review',name + ': unrecognized SameSite value')
        # Cookie values are never copied to reports.
        if 'secure' not in attrs:
            add('COOKIE_SECURE_REVIEW','review',name + ': Secure flag absent')
        if 'httponly' not in attrs:
            add('COOKIE_HTTPONLY_REVIEW','review',name + ': HttpOnly absent; assess whether JavaScript needs this cookie')
        if attrs.get('samesite','').lower()=='none' and 'secure' not in attrs:
            add('COOKIE_SAMESITE_NONE','review',name + ': SameSite=None without Secure')
    summary={level:sum(f['severity']==level for f in findings) for level in ('review','info')}
    return dict(summary=summary,scope='single response; heuristic lint, not a security grade', findings=findings)


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
    parser.add_argument('--format',choices=('json','html'),default='json')
    parser.add_argument('--output',type=Path,help='Write a new report file; refuses overwrite')
    parser.add_argument('--fail-on-review',action='store_true',help='Exit 1 on review findings; errors exit 2')
    args=parser.parse_args()
    try:
        if args.fixture:
            data=json.loads(args.fixture.read_text())
            if not isinstance(data,dict): raise ValueError('Fixture must be a JSON object')
            status=data.get('status',200)
            if type(status) is not int or not 100<=status<=599: raise ValueError('Status must be an HTTP integer from 100 to 599')
            report=audit(data['headers'],data.get('scheme','https'))
        else:
            status,headers,scheme=fetch(args.url); report=audit(headers,scheme)
        report['status']=status
        output=render_html(report) if args.format=='html' else json.dumps(report,indent=2)
        if args.output:
            with args.output.open('x',encoding='utf-8') as stream: stream.write(output+'\n')
        else: print(output)
        if args.fail_on_review and report['summary']['review']: parser.exit(1)
    except (OSError,ValueError,KeyError,http.client.HTTPException) as exc:
        parser.exit(2, f'Cannot audit response: {exc}\n')

if __name__=='__main__': main()
