# Security policy

`pyhtmlclean` is a security library. Please report vulnerabilities privately
rather than opening a public issue with a working exploit.

## Reporting

Open a private security advisory on the repository host. Include:

- the pyhtmlclean version and Python version
- a minimal input string and policy
- the sanitized output you expected and the output you received
- whether the output is inserted into HTML body, attribute, script, style or URL context

Please do not include secrets, customer data or personal information in a report.

## Supported versions

Security fixes are applied to the latest minor release line. Users should pin
a release and upgrade promptly when a security release is published.

## Scope

In scope:

- script execution or event handler execution in sanitized output
- dangerous URL schemes surviving in URL-bearing attributes
- mutation XSS caused by namespace confusion, comments, CDATA or malformed markup
- output that is not idempotent after a second sanitize pass
- resource exhaustion caused by nonlinear tokenizer or sanitizer behavior

Out of scope:

- attacks that require a custom policy explicitly allowing unsafe content
- inserting sanitized output into a JavaScript, CSS or attribute context without the escaping required by that context
- phishing or tracking risk from user-selected elements and links that are otherwise valid HTML
- vulnerabilities in a web framework, browser or application using the library

`strip_html` returns plain text, not HTML-safe markup. It must be escaped if it
is later inserted into HTML.
