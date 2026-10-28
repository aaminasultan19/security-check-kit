# security-check-kit

A small command-line tool that turns a handful of real security checks into
automated, repeatable tests you can re-run against a web app anytime, instead
of manually re-testing by hand every time the app changes.

## Why I built this

I work as an Application Security Analyst, and I helped build an internal
tool at my job that does something similar on a much larger scale. This
project is not that tool and contains none of its code (that code belongs to
my employer) - it's my own small version, built from scratch, to practice and
show the underlying idea: real security checks, written once, run as often
as you want.

## What it checks

The tool currently runs 3 checks against the target app:

1. **IDOR (Insecure Direct Object Reference) on shopping baskets.**
   Can a logged-in user view another user's basket just by changing the
   basket ID? It registers two throwaway accounts, logs both in, and tries
   to read one user's basket using the other user's login token.

2. **Broken authentication on a protected endpoint.**
   Does the server correctly reject a request with no login token, or a
   fake one? It requests a real user's basket with no Authorization header,
   and again with a made-up token, and checks that both are blocked.

3. **Rate limiting on login.**
   Does the login endpoint slow down or block rapid repeated attempts
   (as in a password-guessing attack)? It sends a burst of failed login
   attempts and checks whether any get blocked with a 429 status.

Each check prints a clear PASS or FAIL, a plain-English reason, and the
evidence behind it (the actual requests sent and responses received), so
you're never just told "FAIL" with no way to see why.

## A known, expected result: the rate-limit check will FAIL

OWASP Juice Shop (the target app used here) has no rate limiting on login by
default. That means the rate-limit check will reliably report FAIL against
it. This isn't a bug in this tool - it's the tool correctly catching a real
gap in the target app. The check's output says so explicitly
("no rate limiting detected"), rather than looking like an error.

## Target app: OWASP Juice Shop

This tool is built and tested against
[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), a
deliberately vulnerable web application made specifically for practicing
security testing, legally and safely.

**Only run this tool against apps you own or are explicitly authorized to
test**, such as Juice Shop. Running these checks against a real website
without permission would be illegal.

## How to run it

1. Install [Docker](https://www.docker.com/) and start it.

2. Run Juice Shop locally:

   ```bash
   docker run -d -p 3001:3000 bkimminich/juice-shop
   ```

   This makes Juice Shop available at `http://localhost:3001`.

3. Install the Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the checks:

   ```bash
   python main.py --url http://localhost:3001
   ```

## License

MIT - see [LICENSE](LICENSE).
