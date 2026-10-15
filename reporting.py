"""Self-contained, script-free report rendering; all report text is escaped."""
from html import escape


def render_html(report):
    def safe(value):
        return escape(str(value), quote=True)
    rows=''.join('<tr><td>'+safe(f['severity'])+'</td><td>'+safe(f['rule'])+
                 '</td><td>'+safe(f['detail'])+'</td></tr>' for f in report['findings'])
    if not rows:
        rows='<tr><td colspan="3">No findings from these checks. This is not a security guarantee.</td></tr>'
    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Web Security Header Audit</title>
<style>body{background:#0b1220;color:#dbe7f4;font:16px system-ui;margin:0;padding:4vw}
main{max-width:1100px;margin:auto}h1{color:#60a5fa}p{line-height:1.6}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:14px;border-bottom:1px solid #334155;overflow-wrap:anywhere}
th{color:#93c5fd}section{overflow-x:auto}footer{margin-top:2rem;color:#94a3b8}</style></head><body><main>
<h1>Web Security Header Audit</h1><p>Single-response configuration review</p>'''+(
        '<p>Status: '+safe(report.get('status','unknown'))+' | Review: '+safe(report['summary']['review'])+
        ' | Info: '+safe(report['summary']['info'])+'</p><p>'+safe(report['scope'])+'</p>'
        '<section><table><thead><tr><th>Level</th><th>Rule</th><th>Details</th></tr></thead><tbody>'+rows+
        '</tbody></table></section><footer>Review findings in application context. Cookie values are omitted. '
        'This report does not establish exploitability.</footer></main></body></html>')
