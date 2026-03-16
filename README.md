# certcheck-bot

A bot to check the validity of SSL/TLS certificates of a list of domains. If a certificate is due to expire within **14 days**, a GitHub issue is automatically created. When a subsequent check shows that the certificate has been renewed, the issue is automatically closed with a comment.

## How it works

1. A list of domains is maintained in [`domains.csv`](domains.csv).
2. A [GitHub Actions workflow](.github/workflows/certcheck.yml) runs the check **daily at 08:00 UTC** and can also be triggered manually.
3. For each domain the script:
   - Connects to the domain on port 443 and reads the SSL/TLS certificate expiry date.
   - If the certificate expires in **less than 14 days** and no open issue exists for that domain → a new issue is created and labelled `ssl-expiry`.
   - If the certificate expires in **less than 14 days** and an open issue already exists → nothing happens (no duplicate).
   - If the certificate is **valid for 14 or more days** and an open issue exists → the issue is closed with a comment confirming the renewal.

## Adding domains

Edit [`domains.csv`](domains.csv) and add one domain per line under the `domain` header:

```csv
domain
example.com
mysite.org
```

## Running locally

```bash
pip install -r requirements.txt
export GITHUB_TOKEN=<your personal access token>
export GITHUB_REPOSITORY=<owner/repo>
python certcheck.py
```

## Running the tests

```bash
pip install -r requirements.txt pytest
pytest tests/
```
