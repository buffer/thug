import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestFileAPI(object):
    cwd_path = os.path.dirname(os.path.realpath(__file__))
    misc_path = os.path.join(cwd_path, os.pardir, "samples/misc")

    def do_perform_test(self, caplog, sample, expected):
        thug = ThugAPI()

        thug.set_useragent("osx10chrome97")
        thug.log_init(sample)
        thug.run_local(sample)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_blob(self, caplog):
        sample = os.path.join(self.misc_path, "testFileAPIBlob.html")
        expected = [
            "BLOB 1 type: application/json",
            "BLOB 1 size: 22",
            "BLOB 2 type: text/plain",
            "BLOB 2 size: 5",
            "BLOB 3 size: 18",
            "BLOB 2 text: hello",
            'BLOB 3 text: "hello": "world"',
            "BLOB1 typeof(result): object",
            "BLOB 4 text: abc",
        ]

        self.do_perform_test(caplog, sample, expected)

    def test_file(self, caplog):
        sample = os.path.join(self.misc_path, "testFileAPIFile.html")
        expected = ["File name: sample.zip", "File type: application/zip"]

        self.do_perform_test(caplog, sample, expected)
