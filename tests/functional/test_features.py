import os
import json
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestFeatures(object):
    thug_path = os.path.dirname(os.path.realpath(__file__)).split("thug")[0]
    features_path = os.path.join(thug_path, "thug", "samples/features")
    expected_path = os.path.join(thug_path, "thug/tests/functional/features.json")
    
    with open(expected_path) as fd:
        expected = json.load(fd)

    def do_perform_test(self, caplog, sample):
        thug = ThugAPI()

        thug.log_init(sample)

        thug.set_useragent('win7ie90')
        thug.set_verbose()
        thug.set_json_logging()

        thug.reset_features_logging()
        assert thug.get_features_logging() == False

        thug.set_features_logging()
        assert thug.get_features_logging() == True

        thug.log_init(sample)
        thug.run_local(sample)
        thug.log_event()

        for r in caplog.records:
            try:
                features = json.dumps(r)
            except Exception:
                continue

            if not isinstance(features, dict):
                continue

            if "html_count" not in features:
                continue

            for url in self.expected:
                if not url.endswith(sample):
                    continue

                for key in features:
                    assert features[key] == self.expected[url][key]

    def test_test_1(self, caplog):
        sample = os.path.join(self.features_path, "test1.html")
        self.do_perform_test(caplog, sample)
