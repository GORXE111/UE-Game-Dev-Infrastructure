"""Regression tests for the read-only public delivery gate."""

from email.message import Message
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from urllib.error import HTTPError

import verify_public_delivery as delivery


class Response(BytesIO):
    def __init__(self, data, url, status=200, **headers):
        super().__init__(data)
        self.url = url
        self.status = status
        self.headers = Message()
        for name, value in headers.items():
            self.headers[name] = value

    def geturl(self):
        return self.url


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = "https://updates.example.test"
        self.path = "/samplegame/versions/101/file.pak"
        self.data = bytes(range(256)) * 41
        self.expected = {"size": len(self.data), "sha256": delivery.sha(self.data)}
        self.web = delivery.Readback(self.endpoint, 30)

    def test_same_size_tail_corruption_fails_full_download(self):
        corrupted = self.data[:-1] + b"x"
        self.web.opener.open = lambda request, timeout: Response(
            corrupted, request.full_url, **{"Content-Length": str(len(corrupted)), "Cache-Control": "immutable"})
        with self.assertRaisesRegex(ValueError, "Complete HTTPS size/SHA-256 differs"):
            self.web.full(self.path, self.expected)

    def test_head_and_both_ranges_use_bytes_from_the_verified_download(self):
        requests = []

        def open_response(request, timeout):
            self.assertEqual(request.get_header("Accept-encoding"), "identity")
            method, byte_range = request.get_method(), request.get_header("Range")
            requests.append((method, byte_range))
            headers = {"Content-Length": str(len(self.data)), "Cache-Control": "public, immutable"}
            if method == "HEAD":
                return Response(b"", request.full_url, **headers)
            if byte_range:
                start, end = map(int, byte_range.removeprefix("bytes=").split("-"))
                data = self.data[start:end + 1]
                return Response(data, request.full_url, 206, **{"Content-Length": str(len(data)),
                                "Content-Range": f"bytes {start}-{end}/{len(self.data)}"})
            return Response(self.data, request.full_url, **headers)

        self.web.opener.open = open_response
        completed, prefix, tail = self.web.full(self.path, self.expected)
        self.assertEqual(completed["sha256"], self.expected["sha256"])
        result = self.web.range_checks(self.path, len(self.data), prefix, tail)
        self.assertEqual(result["verifiedRanges"], 2)
        self.assertEqual(requests, [("GET", None), ("HEAD", None), ("GET", "bytes=0-4095"), ("GET", "bytes=6400-10495")])

    def test_missing_file_must_not_be_cached(self):
        for value, valid in (("no-store", True), ("immutable", False), ("no-store, immutable", False)):
            with self.subTest(value=value):
                def missing(request, timeout):
                    raise HTTPError(request.full_url, 404, "missing", {"Cache-Control": value}, BytesIO())

                self.web.opener.open = missing
                if valid:
                    self.assertEqual(self.web.missing(self.path)["status"], 404)
                else:
                    with self.assertRaisesRegex(ValueError, "missing-file cache policy"):
                        self.web.missing(self.path)

    def test_wrong_plan_digest_stops_at_local_validation(self):
        with TemporaryDirectory() as directory:
            plan = Path(directory) / "prepared.json"
            plan.write_bytes(b'{"schemaVersion":1}')
            with self.assertRaisesRegex(ValueError, "Prepared publication plan SHA-256 differs"):
                delivery.read_plan(plan, "0" * 64)


if __name__ == "__main__":
    unittest.main()
