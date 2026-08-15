# Public-Path Evidence Audit Starter

A small, public-only worksheet for founders, agencies, and operators who want
to review a conversion path before sharing credentials or changing production
systems.

It is a planning and observation aid, not a security test, accessibility
certification, legal review, or conversion guarantee.

## Run a 10-minute public-path check

Use this as a **landing-page QA checklist**, **pre-launch website checklist**,
or lightweight **conversion-funnel audit** when you need to verify that a
visitor can understand and reach one intended action.

1. Download or copy `route-register.csv` and name one visitor action.
2. Review up to five public routes with `review-checklist.md`.
3. Record only reproducible observations in `finding-log.csv`.
4. Compare your notes with the [completed sample](sample-self-audit.md).

Prefer a browser-sized version? Use the
[free public-path launch checklist](https://offers.allurelabs.ai/public-path-checklist/).

If you want Allure Labs to perform the same bounded, public-only review,
[open a structured audit request](https://github.com/Allura-Gensin/public-path-evidence-audit-starter/issues/new?template=audit-request.yml&title=%5Bpublic-path-checklist%5D%20Audit%20request).
Every request is counted in this repository's public Issues tab, providing a
clear measure of qualified inbound interest. Opening one starts a scope
conversation only; it does not authorize testing, create a contract, or require
payment.

## Capture evidence in GitHub Actions

This repository also contains a dependency-free composite action that records
a small private Markdown report for one to five explicitly named public
routes. It performs GET requests only. It does not follow redirects, retain or
send cookies, execute scripts, submit forms, authenticate, or connect to a
private or special-purpose network address.

```yaml
permissions: {}

steps:
  # Pinned to the exact independently reviewed implementation commit.
  - uses: Allura-Gensin/public-path-evidence-audit-starter@af85ce58fa071c56e4d16d19b77c19a2a69dbd9e
    id: evidence
    with:
      urls-json: '["https://example.com/", "https://example.com/pricing"]'
```

The action exposes `report-path`, `route-count`, and `html-count` outputs. It
does not upload, print, cache, commit, or publish the report. A caller can make
an explicit downstream decision about the private `report-path`; never publish
a report containing information that should not be public. See
[the manual example workflow](.github/workflows/public-path-evidence-example.yml)
for a complete job.

Input URLs must use standard-port HTTPS, contain no username or password, and
be publicly reachable without credentials. URL fragments, private or
special-purpose DNS answers, mixed public/private DNS answers, IP literals,
query strings, and self-hosted runners are refused. Never provide tokens,
customer data, signed links, private URLs, or other secrets. The action needs no
GitHub token or repository permission.

Version 1 runs only on GitHub-hosted Linux runners. Each route has one 15-second
deadline covering DNS, connection, TLS, response headers, and body, and the
whole run is capped at 60 seconds. Python's standard HTTP parser enforces its
own per-line and header-count limits; a response wrapper also counts the status
line and headers while that parser reads them and aborts above a 64 KiB
aggregate, with the socket still deadline-bound. Reports
are created once at `$RUNNER_TEMP/public-path-evidence-audit/report.md` with a
private directory and file mode, and a pre-existing path is refused.

For local verification, run:

```bash
python3 -m unittest discover -s tests -v
```

## Included

- `route-register.csv` — record up to five public routes and one visitor action.
- `finding-log.csv` — separate observations from hypotheses and decisions.
- `review-checklist.md` — a practical, public-only review sequence.
- `sample-self-audit.md` — three real, carefully bounded findings from an
  Allure Labs-owned public homepage.

## Use safely

1. Start with pages available to any ordinary visitor.
2. State the visitor action you are reviewing before collecting observations.
3. Do not log in, create an account, enter form data, submit a form, make a
   purchase, bypass controls, or access non-public systems.
4. Record a fact with a route, viewport, time, and a concise reproduction note.
5. Mark anything uncertain as a question for the owner instead of treating it
   as a defect.

## Want a bounded review?

First, [read the sample self-audit](sample-self-audit.md) to see how an
observation, rationale, and recommendation are kept separate.

Allure Labs offers a fixed-scope public conversion-path review for up to five
routes, desktop and mobile observation, and a short evidence report. It is
separate from this free starter and does not require credentials. A one-minute
brief prepares a complete scope-request email without storing your input.

<https://offers.allurelabs.ai/audit/>

GitHub users can also [open a public, structured audit request](https://github.com/Allura-Gensin/public-path-evidence-audit-starter/issues/new?template=audit-request.yml).
The request is only a scope conversation: it creates no contract, payment, or
testing authorization. Do not put credentials, customer data, private links,
or payment information in a public issue.

## License

MIT. See [LICENSE](LICENSE).
