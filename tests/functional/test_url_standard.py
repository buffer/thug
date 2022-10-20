import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestURLStandard(object):
    cwd_path        = os.path.dirname(os.path.realpath(__file__))
    misc_path       = os.path.join(cwd_path, os.pardir, "samples/misc")

    def do_perform_test(self, caplog, sample, expected):
        thug = ThugAPI()

        thug.set_useragent('osx10chrome97')
        thug.log_init(sample)
        thug.run_local(sample)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_url(self, caplog):
        sample   = os.path.join(self.misc_path, "testURL.html")
        expected = ['URL1 pathname: /foo/bar',
                    'URL1 protocol: https:',
                    'URL2 href: https://www.example.com:8080/cats#foo',
                    'URL2 host: www.example.com:8080',
                    'URL2 hostname: www.example.com',
                    'URL2 origin: https://www.example.com:8080',
                    'URL2 pathname: /cats',
                    'URL2 protocol: https:',
                    'URL2 port: 8080',
                    'URL2 hash: #foo',
                    'URL3 href: https://example.com',
                    'URL4 href: https://example.com:8081',
                    'URL5 href: https://example.com/dogs#foo',
                    'URL6 search: foo=bar',
                    'URL6 href: https://username2@www.example.com:8080/?foo=bar',
                    'URL7 username: username2',
                    'URL7 password: password2',
                    'URL7 href: https://username2:password2@www.example.com:8080',
                    'URL8 href: https://:password@www.example.com',
                    'URL8 href: https://:password2@www.example.com']

        self.do_perform_test(caplog, sample, expected)

    def test_urlsearchparams(self, caplog):
        sample   = os.path.join(self.misc_path, "testURLSearchParams.html")
        expected = ['params1.toString() = q=URLUtils.searchParams&topic=api',
                    'params2.toString() = key=730d67&foo=bar',
                    'params3.toString() before set = p=params3&foo=bar&foo=baz',
                    'params3.get("p") === "params3": true',
                    'params3.get("q") === null: true',
                    'params3.has("foo"): true',
                    'params3.get("foo"): bar',
                    'params3.toString() after set = p=params3&foo=overwrited',
                    'params3.toString() after delete = p=params3',
                    'params3.has("foo") after delete: false',
                    'params4.has("query"): true',
                    'params4.get("query"): value',
                    'params5.has("foo"): true',
                    'params6.has("foo"): true',
                    'params7.toString() before sort = foo=foz&foo=bar&bar=baz',
                    'params7.toString() after sort = bar=baz&foo=foz&foo=bar']

        self.do_perform_test(caplog, sample, expected)
