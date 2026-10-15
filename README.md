# Web Security Header Auditor

![Web Security Header Auditor workflow](assets/workflow.svg)

Single-response linting for CSP, HSTS, framing, nosniff, referrer policy and cookie flags.

**Fresh portfolio implementation • Python 3.10+ • Standard library only**

## Run

```bash
python3 --version
python3 auditor.py --fixture examples/headers.json
python3 -m unittest discover -s tests -v
```

## Implemented behavior

- Offline fixtures or one explicit HEAD request. HTTPS uses Python's default certificate verification.
- Redirects are NOT followed. A 3xx or 405 is reported as-is; the tool never silently switches to GET.
- Duplicate headers and cookie attributes are inspected; cookie values are omitted from findings.
- Findings request review. There is no pass score or claim of exploitability.

## Extended checks and reporting

- CSP duplicate directives retain the first occurrence; duplicates and unsafe-eval get explicit review findings.
- Static CORS checks identify wildcard-plus-credentials conflicts, null origins, duplicate headers and invalid credentials values. Wildcard with credentials is a browser-blocked configuration, not proof of credential leakage. Public wildcard access alone is not flagged.
- Cookie checks cover `__Host-`, `__Secure-`, `__Http-`, and `__Host-Http-` prefix requirements, duplicate attributes and invalid SameSite values. Browser support differs; local secure-context exceptions are not modeled.
- JSON reports include review/info counts. Optional dark HTML reports are self-contained, script-free and escape all report text.
- Output files refuse overwrite to protect existing reports. Fixture header pairs, scheme and status are validated.

```bash
# Offline dark report; choose a new output filename on every run
python3 auditor.py --fixture examples/extended-headers.json --format html --output report.html

# CI integration: review findings return 1 after printing valid JSON
python3 auditor.py --fixture examples/extended-headers.json --fail-on-review

# One HEAD request, only against an endpoint you are authorized to assess
python3 auditor.py --url https://example.com --format html --output authorized-report.html
```

Reports remain heuristic: inspect the application before treating a configuration as a vulnerability. Prefix checks are case-sensitive; duplicate cookie attributes still require manual interpretation.

## Scope and limitations

Only header syntax heuristics are checked. CSP parsing is deliberately limited (first policy, no full browser evaluation); multiple policies, nonce/hash interaction and application requirements need manual assessment. Cookie checks do not identify session cookies. No HTML/meta policy parsing, redirect-chain checks, active CORS probing, TLS grading or cookie-jar evaluation. Static CORS checks cannot determine origin reflection or cross-origin data exposure. Live mode is a local CLI, not a hardened public URL-fetching service. Do not expose it as a server-side fetch endpoint. Network errors exit 2. By default, exit 0 means collection completed even if findings exist. With `--fail-on-review`, review findings exit 1; informational-only reports still exit 0. Collection, input and output errors exit 2.

## Validation

17 unit tests passed locally on Python 3.12.14. Synthetic CLI examples were executed and results are included under `examples/`. No customer data, historical lab results or production effectiveness is claimed. CI configuration is supplied; remote CI status must be checked after publishing.

## Files

- `auditor.py` — implementation and CLI.
- `reporting.py` — escaped, offline HTML rendering.
- `tests/test_main.py` — regression and boundary tests.
- `examples/` — synthetic inputs and generated output.
- `assets/workflow.svg` — project-specific animation with reduced-motion support.
- `.github/workflows/ci.yml` — pinned-action CI.

## Safe operation

Use inputs and hosts you own or are authorized to assess. Review reports before publication; real files, headers and logs can contain sensitive information. These tools do not establish that a system is secure or compromised.

## Reference

https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy

https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie

https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin
