import csv
import re
import unittest


class TestEngineHash(unittest.TestCase):
    CSV_FILE = "enginehash.csv"
    EXPECTED_HEADERS = ["version", "Engine_commit", "Snapshot_Hash"]

    def setUp(self):
        with open(self.CSV_FILE, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            self.rows = list(reader)

    def test_headers(self):
        with open(self.CSV_FILE, newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            headers = [h.strip() for h in next(reader)]
        self.assertEqual(headers, self.EXPECTED_HEADERS)

    def test_no_empty_rows(self):
        for i, row in enumerate(self.rows, start=2):
            for col in self.EXPECTED_HEADERS:
                self.assertTrue(
                    row[col].strip(),
                    f"Row {i}: column '{col}' is empty",
                )

    def test_engine_commit_is_sha1(self):
        sha1_re = re.compile(r"^[0-9a-f]{40}$")
        for i, row in enumerate(self.rows, start=2):
            commit = row["Engine_commit"].strip()
            self.assertRegex(
                commit,
                sha1_re,
                f"Row {i}: Engine_commit '{commit}' is not a valid 40-char SHA-1",
            )

    def test_snapshot_hash_is_md5(self):
        md5_re = re.compile(r"^[0-9a-f]{32}$")
        for i, row in enumerate(self.rows, start=2):
            snap = row["Snapshot_Hash"].strip()
            self.assertRegex(
                snap,
                md5_re,
                f"Row {i}: Snapshot_Hash '{snap}' is not a valid 32-char MD5 hash",
            )

    def test_version_format(self):
        # Allow both ASCII hyphen and Unicode non-breaking hyphen (U+2011)
        version_re = re.compile(
            r"^v?\d+\.\d+[\w.\-+\u2011]*$"
        )
        for i, row in enumerate(self.rows, start=2):
            version = row["version"].strip()
            self.assertRegex(
                version,
                version_re,
                f"Row {i}: version '{version}' does not match expected format",
            )

    def test_unique_versions(self):
        versions = [row["version"].strip() for row in self.rows]
        self.assertEqual(
            len(versions),
            len(set(versions)),
            "Duplicate version entries found in CSV",
        )

    def test_unique_engine_commits(self):
        commits = [row["Engine_commit"].strip() for row in self.rows]
        self.assertEqual(
            len(commits),
            len(set(commits)),
            "Duplicate Engine_commit entries found in CSV",
        )


if __name__ == "__main__":
    unittest.main()
