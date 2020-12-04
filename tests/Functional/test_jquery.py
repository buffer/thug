import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestJQuerySamples(object):
    cwd_path    = os.path.dirname(os.path.realpath(__file__))
    jquery_path = os.path.join(cwd_path, os.pardir, "samples/jQuery")

    def do_perform_test(self, caplog, sample, expected):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_events('click,storage')
        thug.disable_cert_logging()
        thug.set_file_logging()
        thug.set_json_logging()
        thug.set_features_logging()
        thug.set_ssl_verify()
        thug.get_ssl_verify()
        thug.log_init(sample)
        thug.run_local(sample)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_jquery_1(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-1.html")
        expected = ["[Window] Alert Text: Ready"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_2(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-2.html")
        expected = ['<a class="foobar" href="http://www.google.com" id="myId">jQuery</a>']

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_3(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-3.html")
        expected = ['<div class="notMe">',
                    '<div class="myClass" foo="bar">div class="myClass"</div>',
                    '<span class="myClass" foo="bar">span class="myClass"</span>']

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_4(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-4.html")
        expected = ['<div foo="bar" id="notMe" name="whoa">Aieeee</div>']

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_5(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-5.html")
        expected = ['<div class="myClass" foo="bar" name="whoa">Aieeee</div>']

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_6(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-6.html")
        expected = ['<div class="myClass"><p>Just a modified p</p></div>',
                    '<div class="myClass"><foo>Just a foo</foo></div>']

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_7(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-7.html")
        expected = ["<h3>New text for the third h3</h3>"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_8(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-8.html")
        expected = ["<h3>New text for the first h1</h3>",
                    "<h3>New text for the third h3</h3>"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_9(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-9.html")
        expected = ['<p>Yet another p</p><div class="container1">',
                    '<div class="inner1">Hello<p>Just a p</p></div>',
                    '<div class="inner2">Goodbye<p>Just another p</p></div>']

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_10(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-10.html")
        expected = ["<ul><li>list item</li></ul>"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_11(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-11.html")
        expected = ['<div id="target"><td>Hello World</td></div>']

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_12(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-12.html")
        expected = ["[Window] Alert Text: 2",
                    "[Window] Alert Text: Foo"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_14(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-14.html")
        expected = ["[Window] Alert Text: 1",
                    "[Window] Alert Text: child"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_15(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-15.html")
        expected = ["[Window] Alert Text: parent"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_16(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-16.html")
        expected = ["[Window] Alert Text: child",
                    "[Window] Alert Text: parent",
                    "[Window] Alert Text: grandparent"]

        self.do_perform_test(caplog, sample, expected)

    def disabled_test_jquery_17(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-17.html")
        expected = ["[Window] Alert Text: child",
                    "[Window] Alert Text: parent"]

        self.do_perform_test(caplog, sample, expected)

    def disabled_test_jquery_18(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-18.html")
        expected = ["[Window] Alert Text: child"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_19(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-19.html")
        expected = ["[Window] Alert Text: child"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_20(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-20.html")
        expected = ["[Window] Alert Text: parent",
                    "[Window] Alert Text: surrogateParent1",
                    "[Window] Alert Text: surrogateParent2"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_21(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-21.html")
        expected = ["[Window] Alert Text: child",
                    "[Window] Alert Text: parent",
                    "[Window] Alert Text: surrogateParent1",
                    "[Window] Alert Text: surrogateParent2"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_22(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-22.html")
        expected = ["[Window] Alert Text: surrogateParent1"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_24(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-24.html")
        expected = ["[Window] Alert Text: surrogateParent1",
                    "[Window] Alert Text: surrogateParent2"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_25(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-25.html")
        expected = ["[Window] Alert Text: surrogateParent1"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_26(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-26.html")
        expected = ["[Window] Alert Text: surrogateParent2"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_27(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-27.html")
        expected = ["[Window] Alert Text: parent",
                    "[Window] Alert Text: surrogateParent1"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_28(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-28.html")
        expected = ["[Window] Alert Text: surrogateParent1"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_29(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-29.html")
        expected = ["[Window] Alert Text: parent"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_32(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-32.html")
        expected = ["[Window] Alert Text: Inside the callback",
                    "__version__",
                    "__configuration_path__"]

        self.do_perform_test(caplog, sample, expected)

    def test_jquery_33(self, caplog):
        sample   = os.path.join(self.jquery_path, "test-jquery-33.html")
        expected = ["[Window] Alert Text: Done",
                    "[Window] Alert Text: The request is complete"]

        self.do_perform_test(caplog, sample, expected)
