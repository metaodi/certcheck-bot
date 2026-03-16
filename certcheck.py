import ssl
import socket
import csv
import os
import sys
from datetime import datetime, timezone

from github import Github, GithubException

EXPIRY_THRESHOLD_DAYS = 14
BOT_LABEL_NAME = "ssl-expiry"
BOT_LABEL_COLOR = "e11d48"
BOT_LABEL_DESCRIPTION = "SSL/TLS certificate expiry issue"


def get_cert_expiry(domain, timeout=10):
    """Return the UTC expiry datetime for the SSL/TLS certificate of *domain*."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((domain, 443), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
    expiry_str = cert["notAfter"]
    expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
    return expiry_date.replace(tzinfo=timezone.utc)


def ensure_label_exists(repo):
    """Create the bot label in *repo* if it does not already exist."""
    try:
        repo.get_label(BOT_LABEL_NAME)
    except GithubException:
        repo.create_label(BOT_LABEL_NAME, BOT_LABEL_COLOR, BOT_LABEL_DESCRIPTION)


def find_open_issue(repo, domain):
    """Return the first open issue that was created by this bot for *domain*, or None."""
    try:
        label = repo.get_label(BOT_LABEL_NAME)
    except GithubException:
        return None
    expected_title = f"SSL certificate for {domain} expires soon"
    for issue in repo.get_issues(state="open", labels=[label]):
        if issue.title == expected_title:
            return issue
    return None


def read_domains(csv_path):
    """Read domain names from the first column of a CSV file (skipping header)."""
    domains = []
    with open(csv_path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            domain = row.get("domain", "").strip()
            if domain:
                domains.append(domain)
    return domains


def check_domain(repo, domain, now):
    """Check the certificate for *domain* and create/close issues as needed."""
    try:
        expiry_date = get_cert_expiry(domain)
    except Exception as exc:
        print(f"  ERROR checking {domain}: {exc}")
        return

    days_remaining = (expiry_date - now).days
    print(f"  {domain}: expires {expiry_date.date()} ({days_remaining} days remaining)")

    existing_issue = find_open_issue(repo, domain)

    if days_remaining < EXPIRY_THRESHOLD_DAYS:
        if existing_issue:
            print(f"    -> Open issue already exists: #{existing_issue.number}")
        else:
            title = f"SSL certificate for {domain} expires soon"
            body = (
                f"The SSL/TLS certificate for **{domain}** will expire on "
                f"**{expiry_date.strftime('%Y-%m-%d %H:%M:%S UTC')}** "
                f"({days_remaining} days remaining).\n\n"
                "Please renew the certificate before it expires."
            )
            issue = repo.create_issue(
                title=title,
                body=body,
                labels=[BOT_LABEL_NAME],
            )
            print(f"    -> Created issue: #{issue.number}")
    else:
        if existing_issue:
            comment = (
                f"The SSL/TLS certificate for **{domain}** has been renewed. "
                f"It is now valid until **{expiry_date.strftime('%Y-%m-%d %H:%M:%S UTC')}** "
                f"({days_remaining} days remaining). Closing this issue."
            )
            existing_issue.create_comment(comment)
            existing_issue.edit(state="closed")
            print(f"    -> Certificate renewed; closed issue: #{existing_issue.number}")


def main():
    github_token = os.environ.get("GITHUB_TOKEN")
    repo_name = os.environ.get("GITHUB_REPOSITORY")

    if not github_token:
        print("Error: GITHUB_TOKEN environment variable is not set.", file=sys.stderr)
        sys.exit(1)
    if not repo_name:
        print("Error: GITHUB_REPOSITORY environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    csv_path = os.environ.get("DOMAINS_CSV", "domains.csv")
    if not os.path.isfile(csv_path):
        print(f"Error: domains file not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    g = Github(github_token)
    repo = g.get_repo(repo_name)
    ensure_label_exists(repo)

    domains = read_domains(csv_path)
    if not domains:
        print("No domains found in CSV file.")
        return

    now = datetime.now(timezone.utc)
    print(f"Checking {len(domains)} domain(s) at {now.strftime('%Y-%m-%d %H:%M:%S UTC')}...")
    for domain in domains:
        check_domain(repo, domain, now)


if __name__ == "__main__":
    main()
