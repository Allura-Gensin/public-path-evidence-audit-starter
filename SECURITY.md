# Security boundary

The Public-Path Evidence Check is a narrow observation tool, not a crawler or
security scanner. Version 1 runs only on GitHub-hosted Linux runners and accepts one
to five ordinary public HTTPS routes.

It refuses credentials, query strings, fragments, IP literals, nonstandard
ports, private or special-purpose DNS answers, mixed public/private DNS
answers, redirects, encoded bodies, and self-hosted runners. It sends one
unauthenticated GET per accepted route, requests no compressed response, pins
the connection to a validated public DNS answer, verifies TLS for the supplied
hostname, and stores no raw HTML, headers, cookies, or secrets.

DNS is capped at 16 answers and five seconds. One 15-second deadline covers
DNS, connection, TLS, response headers, and response body for each route, with
a 60-second whole-run cap. Python's standard HTTP parser limits individual
header lines and header count; a response wrapper counts the status line and
headers during parsing and aborts above a 64 KiB aggregate while the socket is
still deadline-bound.

The generated report is created mode `0600` in the fresh fixed mode `0700`
directory `$RUNNER_TEMP/public-path-evidence-audit`. A pre-existing directory
or report is refused. The Action does not upload,
print, cache, commit, or publish it. Callers are responsible for deciding
whether any downstream use of the report is appropriate.

Never submit private URLs, signed links, tokens, credentials, customer data,
personal data, or confidential routes. A successful report is not permission
to test a system and is not a security, accessibility, legal, or launch
certification.

To report a vulnerability in this repository, use GitHub's private
vulnerability-reporting feature if it is available. Do not include secrets or
third-party data in a public issue.
