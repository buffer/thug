import os
import logging

from thug.Analysis.virustotal.VirusTotal import VirusTotal
from thug.ThugAPI.ThugOpts import ThugOpts

log = logging.getLogger("Thug")
log.configuration_path = "/etc/thug"
log.personalities_path = "/etc/thug/personalities"
log.ThugOpts = ThugOpts()


class TestVirusTotal(object):
    cwd_path = os.path.dirname(os.path.realpath(__file__))
    samples_path = os.path.join(cwd_path, os.pardir, os.pardir, "tests/test_files")

    pe_path = os.path.join(samples_path, "sample.exe")
    
    def build_sample(self):
        with open(self.pe_path, "rb") as fd:
            data = fd.read()
            
        sample = {
            'md5' : '52bfb8491cbf6c39d44d37d3c59ef406'
        }

        return data, sample

    def do_perform_test(self, caplog, expected):
        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_invalid_conf(self, caplog):
        expected = ['[WARNING] VirusTotal disabled (no configuration file found)', ]

        log.configuration_path = "/etc/invalid"
        log.personalities_path = "/etc/thug/personalities"

        vt = VirusTotal()

        assert vt.enabled is False

        data, sample = self.build_sample()
        vt.analyze(data, sample, '/tmp')

        self.do_perform_test(caplog, expected)

    def test_submit(self, caplog):
        log.configuration_path = "/etc/thug"
        log.personalities_path = "/etc/thug/personalities"

        vt = VirusTotal()

        assert vt.enabled is True

        data, sample = self.build_sample()
        vt.submit(data, sample)
