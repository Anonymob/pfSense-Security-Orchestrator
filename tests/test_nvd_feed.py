import unittest
from unittest.mock import patch
from io import BytesIO

from pfsense_guard.nvd_feed import fetch_pfSense_candidates


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return b'{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2099-0001","published":"2099-01-01T00:00:00.000","lastModified":"2099-01-02T00:00:00.000","descriptions":[{"lang":"en","value":"pfSense example issue"}],"references":[{"url":"https://example.invalid/advisory"}]}}]}'


class NvdFeedTests(unittest.TestCase):
    @patch("urllib.request.urlopen", return_value=FakeResponse())
    def test_parse_candidate_without_auto_validation(self, _mock):
        result = fetch_pfSense_candidates()
        self.assertEqual(result["total_results"], 1)
        self.assertEqual(result["candidates"][0]["id"], "CVE-2099-0001")
        self.assertEqual(result["candidates"][0]["review_status"], "unreviewed_candidate")


if __name__ == "__main__":
    unittest.main()
