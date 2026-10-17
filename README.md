# SecretScanner

## Usage

Scan a single file:

    python secret_scanner.py test_secrets.txt

Scan a directory recursively:

    python secret_scanner.py ./my_project

Enable detailed logging:

    python secret_scanner.py ./my_project --verbose

Display command-line help:

    python secret_scanner.py --help

## Detection Logic

SecretScanner uses Python's built-in `re` module and a
dictionary of regular-expression patterns.

The patterns detect:

1. Google API keys beginning with AIza.
2. GitHub classic tokens beginning with ghp_.
3. GitHub fine-grained tokens beginning with github_pat_.
4. Stripe secret keys beginning with sk_live_ or sk_test_.
5. Slack bot tokens beginning with xoxb-.
6. JSON Web Tokens (JWTs) with three segments.
7. PEM private-key headers.
8. Password assignments using common variable names.
9. API key and token assignments using common variable names.