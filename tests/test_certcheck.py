import csv
import os
import ssl
import socket
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, mock_open

import pytest

from certcheck import (
    get_cert_expiry,
    find_open_issue,
    read_domains,
    check_domain,
    ensure_label_exists,
    BOT_LABEL_NAME,
    EXPIRY_THRESHOLD_DAYS,
)


# ---------------------------------------------------------------------------
# get_cert_expiry
# ---------------------------------------------------------------------------

def _make_mock_cert(expiry: datetime) -> dict:
    """Return a minimal fake certificate dict with the given expiry date.

    Real SSL certificates use space-padded (not zero-padded) day numbers,
    e.g. "Jan  1 00:00:00 2030 GMT" – replicate that here.
    """
    # strftime("%d") gives zero-padded days; replace leading "0" with " "
    day_str = expiry.strftime("%d").lstrip("0").rjust(2)
    expiry_str = expiry.strftime(f"%b {day_str} %H:%M:%S %Y GMT")
    return {"notAfter": expiry_str}


def test_get_cert_expiry_returns_utc_datetime():
    expiry = datetime(2030, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    cert = _make_mock_cert(expiry)

    mock_ssock = MagicMock()
    mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
    mock_ssock.__exit__ = MagicMock(return_value=False)
    mock_ssock.getpeercert.return_value = cert

    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)

    with patch("socket.create_connection", return_value=mock_sock):
        with patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_ssock):
            result = get_cert_expiry("example.com")

    assert result.tzinfo == timezone.utc
    assert result.year == 2030
    assert result.month == 6
    assert result.day == 15


def test_get_cert_expiry_raises_on_connection_error():
    with patch("socket.create_connection", side_effect=OSError("refused")):
        with pytest.raises(OSError):
            get_cert_expiry("unreachable.invalid")


# ---------------------------------------------------------------------------
# read_domains
# ---------------------------------------------------------------------------

def test_read_domains_returns_list():
    csv_content = "domain\nexample.com\ngithub.com\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as fh:
        fh.write(csv_content)
        tmp_path = fh.name
    try:
        domains = read_domains(tmp_path)
    finally:
        os.unlink(tmp_path)
    assert domains == ["example.com", "github.com"]


def test_read_domains_skips_blank_entries():
    csv_content = "domain\nexample.com\n\ngithub.com\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as fh:
        fh.write(csv_content)
        tmp_path = fh.name
    try:
        domains = read_domains(tmp_path)
    finally:
        os.unlink(tmp_path)
    assert "" not in domains
    assert len(domains) == 2


# ---------------------------------------------------------------------------
# ensure_label_exists
# ---------------------------------------------------------------------------

def test_ensure_label_exists_creates_missing_label():
    from github import GithubException

    repo = MagicMock()
    repo.get_label.side_effect = GithubException(404, "Not Found")

    ensure_label_exists(repo)

    repo.create_label.assert_called_once_with(
        BOT_LABEL_NAME,
        "e11d48",
        "SSL/TLS certificate expiry issue",
    )


def test_ensure_label_exists_does_not_recreate_existing_label():
    repo = MagicMock()
    repo.get_label.return_value = MagicMock()

    ensure_label_exists(repo)

    repo.create_label.assert_not_called()


# ---------------------------------------------------------------------------
# find_open_issue
# ---------------------------------------------------------------------------

def test_find_open_issue_returns_matching_issue():
    domain = "example.com"
    label_mock = MagicMock()
    issue_mock = MagicMock()
    issue_mock.title = f"SSL certificate for {domain} expires soon"

    repo = MagicMock()
    repo.get_label.return_value = label_mock
    repo.get_issues.return_value = [issue_mock]

    result = find_open_issue(repo, domain)
    assert result is issue_mock


def test_find_open_issue_returns_none_when_no_match():
    label_mock = MagicMock()
    issue_mock = MagicMock()
    # "myexample.com" would previously match "example.com" with a substring check
    issue_mock.title = "SSL certificate for myexample.com expires soon"

    repo = MagicMock()
    repo.get_label.return_value = label_mock
    repo.get_issues.return_value = [issue_mock]

    result = find_open_issue(repo, "example.com")
    assert result is None


def test_find_open_issue_returns_none_when_label_missing():
    from github import GithubException

    repo = MagicMock()
    repo.get_label.side_effect = GithubException(404, "Not Found")

    result = find_open_issue(repo, "example.com")
    assert result is None


# ---------------------------------------------------------------------------
# check_domain
# ---------------------------------------------------------------------------

def _make_repo_mock(existing_issue=None):
    label_mock = MagicMock()
    repo = MagicMock()
    repo.get_label.return_value = label_mock
    repo.get_issues.return_value = [existing_issue] if existing_issue else []
    return repo


def test_check_domain_creates_issue_when_cert_expiring_soon():
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(days=5)

    repo = _make_repo_mock()

    with patch("certcheck.get_cert_expiry", return_value=expiry):
        check_domain(repo, "example.com", now)

    repo.create_issue.assert_called_once()
    _, call_kwargs = repo.create_issue.call_args
    assert call_kwargs.get("title") == "SSL certificate for example.com expires soon"


def test_check_domain_no_duplicate_issue():
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(days=5)

    existing = MagicMock()
    existing.title = "SSL certificate for example.com expires soon"
    existing.number = 42
    repo = _make_repo_mock(existing_issue=existing)

    with patch("certcheck.get_cert_expiry", return_value=expiry):
        check_domain(repo, "example.com", now)

    repo.create_issue.assert_not_called()


def test_check_domain_closes_issue_when_cert_renewed():
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(days=60)

    existing = MagicMock()
    existing.title = "SSL certificate for example.com expires soon"
    existing.number = 99
    repo = _make_repo_mock(existing_issue=existing)

    with patch("certcheck.get_cert_expiry", return_value=expiry):
        check_domain(repo, "example.com", now)

    existing.create_comment.assert_called_once()
    existing.edit.assert_called_once_with(state="closed")


def test_check_domain_does_nothing_when_cert_valid_no_issue():
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(days=60)

    repo = _make_repo_mock()

    with patch("certcheck.get_cert_expiry", return_value=expiry):
        check_domain(repo, "example.com", now)

    repo.create_issue.assert_not_called()


def test_check_domain_handles_connection_error(capsys):
    now = datetime.now(timezone.utc)
    repo = MagicMock()

    with patch("certcheck.get_cert_expiry", side_effect=OSError("refused")):
        check_domain(repo, "unreachable.invalid", now)

    repo.create_issue.assert_not_called()
    captured = capsys.readouterr()
    assert "ERROR" in captured.out
