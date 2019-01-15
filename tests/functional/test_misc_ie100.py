import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestMiscSamplesIE(object):
    thug_path = os.path.dirname(os.path.realpath(__file__)).split("thug")[0]
    misc_path = os.path.join(thug_path, "thug", "samples/misc")

    def do_perform_test(self, caplog, sample, expected):
        thug = ThugAPI()

        thug.set_useragent('win7ie100')
        thug.set_events('click,storage')
        thug.disable_cert_logging()

        thug.log_init(sample)
        thug.run_local(sample)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_plugindetect1(self, caplog):
        sample   = os.path.join(self.misc_path, "PluginDetect-0.7.6.html")
        expected = ['AdobeReader version: 9.1.0.0',
                    'Flash version: 10.0.64.0']

        self.do_perform_test(caplog, sample, expected)

    def test_plugindetect2(self, caplog):
        sample   = os.path.join(self.misc_path, "PluginDetect-0.7.8.html")
        expected = ['AdobeReader version: 9,1,0,0',
                    'Flash version: 10,0,64,0',
                    'Java version: 1,6,0,32',
                    'ActiveXObject: javawebstart.isinstalled.1.6.0.0',
                    'ActiveXObject: javaplugin.160_32']

        self.do_perform_test(caplog, sample, expected)

    def test_test1(self, caplog):
        sample   = os.path.join(self.misc_path, "test1.html")
        expected = ['[Window] Alert Text: one']
        self.do_perform_test(caplog, sample, expected)

    def test_test2(self, caplog):
        sample   = os.path.join(self.misc_path, "test2.html")
        expected = ['[Window] Alert Text: Java enabled: true']
        self.do_perform_test(caplog, sample, expected)

    def test_test3(self, caplog):
        sample   = os.path.join(self.misc_path, "test3.html")
        expected = ['[Window] Alert Text: foo']
        self.do_perform_test(caplog, sample, expected)

    def test_testAppendChild(self, caplog):
        sample   = os.path.join(self.misc_path, "testAppendChild.html")
        expected = ["<div>Don't care about me</div>",
                    '<div>Just a sample</div>']
        self.do_perform_test(caplog, sample, expected)

    def test_testClipboardData(self, caplog):
        sample   = os.path.join(self.misc_path, "testClipboardData.html")
        expected = ['Test ClipboardData']
        self.do_perform_test(caplog, sample, expected)

    def test_testCloneNode(self, caplog):
        sample   = os.path.join(self.misc_path, "testCloneNode.html")
        expected = ['<div id="cloned"><q>Can you copy <em>everything</em> I say?</q></div>']
        self.do_perform_test(caplog, sample, expected)

    def test_testCloneNode2(self, caplog):
        sample   = os.path.join(self.misc_path, "testCloneNode2.html")
        expected = ['<button align="left" id="myButton">Clone node</button>']
        self.do_perform_test(caplog, sample, expected)

    def test_testCreateHTMLDocument(self, caplog):
        sample   = os.path.join(self.misc_path, "testCreateHTMLDocument.html")
        expected = ['<html><head><title>New Document</title></head><body><p>This is a new paragraph.</p></body></html>']
        self.do_perform_test(caplog, sample, expected)

    def test_testCreateStyleSheet(self, caplog):
        sample   = os.path.join(self.misc_path, "testCreateStyleSheet.html")
        expected = ['style1.css" rel="stylesheet"></link><link href="style2.css" rel="stylesheet"></link><link href="style3.css" rel="stylesheet"></link><link href="style4']
        self.do_perform_test(caplog, sample, expected)

    def test_testDocumentAll(self, caplog):
        sample   = os.path.join(self.misc_path, "testDocumentAll.html")
        expected = ['<a href="http://www.google.com">Google</a>']
        self.do_perform_test(caplog, sample, expected)

    def test_testDocumentWrite1(self, caplog):
        sample   = os.path.join(self.misc_path, "testDocumentWrite1.html")
        expected = ['Foobar',
                    "Google</a><script>alert('foobar');</script><script language=\"VBScript\">alert('Gnam');</script><script>alert('Aieeeeee');</script></body>"]
        self.do_perform_test(caplog, sample, expected)

    def test_testExternalSidebar(self, caplog):
        sample   = os.path.join(self.misc_path, "testExternalSidebar.html")
        expected = ['[Window] Alert Text: Internet Explorer >= 7.0 or Chrome']
        self.do_perform_test(caplog, sample, expected)

    def test_testGetElementsByClassName(self, caplog):
        sample   = os.path.join(self.misc_path, "testGetElementsByClassName.html")
        expected = ['<div class="example">First</div>',
                    '<div class="example">Hello World!</div>',
                    '<div class="example">Second</div>']
        self.do_perform_test(caplog, sample, expected)

    def test_testInnerHTML(self, caplog):
        sample   = os.path.join(self.misc_path, "testInnerHTML.html")
        expected = ['dude', 'Fred Flinstone']
        self.do_perform_test(caplog, sample, expected)

    def test_testInsertBefore(self, caplog):
        sample   = os.path.join(self.misc_path, "testInsertBefore.html")
        expected = ["<div>Just a sample</div><div>I'm your reference!</div></body></html>"]
        self.do_perform_test(caplog, sample, expected)

    def test_testLocalStorage(self, caplog):
        sample   = os.path.join(self.misc_path, "testLocalStorage.html")
        expected = ["Alert Text: Fired",
                    "Alert Text: bar",
                    "Alert Text: south"]
        self.do_perform_test(caplog, sample, expected)

    def test_testPlugins(self, caplog):
        sample   = os.path.join(self.misc_path, "testPlugins.html")
        expected = ["Shockwave Flash 10.0.64.0",
                    "Windows Media Player 7",
                    "Adobe Acrobat"]
        self.do_perform_test(caplog, sample, expected)

    def test_testLocation1(self, caplog):
        sample   = os.path.join(self.misc_path, "testLocation1.html")
        expected = ["[HREF Redirection (document.location)]",
                    "Content-Location: about:blank --> Location: http://www.antifork.org"]
        self.do_perform_test(caplog, sample, expected)

    def test_testLocation2(self, caplog):
        sample   = os.path.join(self.misc_path, "testLocation2.html")
        expected = ["[HREF Redirection (document.location)]",
                    "Content-Location: about:blank --> Location: http://www.antifork.org"]
        self.do_perform_test(caplog, sample, expected)

    def test_testLocation3(self, caplog):
        sample   = os.path.join(self.misc_path, "testLocation3.html")
        expected = ["[HREF Redirection (document.location)]",
                    "Content-Location: about:blank --> Location: http://www.antifork.org"]
        self.do_perform_test(caplog, sample, expected)

    def test_testLocation4(self, caplog):
        sample   = os.path.join(self.misc_path, "testLocation4.html")
        expected = ["[HREF Redirection (document.location)]",
                    "Content-Location: about:blank --> Location: http://www.antifork.org"]
        self.do_perform_test(caplog, sample, expected)

    def test_testLocation5(self, caplog):
        sample   = os.path.join(self.misc_path, "testLocation5.html")
        expected = ["[HREF Redirection (document.location)]",
                    "Content-Location: about:blank --> Location: http://www.antifork.org"]
        self.do_perform_test(caplog, sample, expected)

    def test_testLocation6(self, caplog):
        sample   = os.path.join(self.misc_path, "testLocation6.html")
        expected = ["[HREF Redirection (document.location)]",
                    "Content-Location: about:blank --> Location: http://www.antifork.org"]
        self.do_perform_test(caplog, sample, expected)

    def test_testMetaXUACompatibleEdge(self, caplog):
        sample   = os.path.join(self.misc_path, "testMetaXUACompatibleEdge.html")
        expected = ["[Window] Alert Text: 10"]
        self.do_perform_test(caplog, sample, expected)

    def test_testMetaXUACompatibleEmulateIE(self, caplog):
        sample   = os.path.join(self.misc_path, "testMetaXUACompatibleEmulateIE.html")
        expected = ["[Window] Alert Text: 8"]
        self.do_perform_test(caplog, sample, expected)

    def test_testMetaXUACompatibleIE(self, caplog):
        sample   = os.path.join(self.misc_path, "testMetaXUACompatibleIE.html")
        expected = ["[Window] Alert Text: 10"]
        self.do_perform_test(caplog, sample, expected)

    def test_testNode(self, caplog):
        sample   = os.path.join(self.misc_path, "testNode.html")
        expected = ['<a href="/" id="thelink">test</a>',
                    "thediv"]
        self.do_perform_test(caplog, sample, expected)

    def test_testNode2(self, caplog):
        sample   = os.path.join(self.misc_path, "testNode2.html")
        expected = ['<a href="/bar.html" id="thelink">test</a>',
                    "thediv2"]
        self.do_perform_test(caplog, sample, expected)

    def test_testQuerySelector(self, caplog):
        sample   = os.path.join(self.misc_path, "testQuerySelector.html")
        expected = ["Alert Text: Have a Good life.",
                    "CoursesWeb.net"]
        self.do_perform_test(caplog, sample, expected)

    def test_testQuerySelector2(self, caplog):
        sample   = os.path.join(self.misc_path, "testQuerySelector2.html")
        expected = ['<li class="aclass">CoursesWeb.net</li>',
                    "<li>MarPlo.net</li>",
                    '<li class="aclass">php.net</li>']
        self.do_perform_test(caplog, sample, expected)

    def test_testScope(self, caplog):
        sample   = os.path.join(self.misc_path, "testScope.html")
        expected = ["foobar",
                    "foo",
                    "bar",
                    "True",
                    "3",
                    "2012-10-07 11:13:00",
                    "3.14159265359",
                    "/foo/i"]
        self.do_perform_test(caplog, sample, expected)

    def test_testSessionStorage(self, caplog):
        sample   = os.path.join(self.misc_path, "testSessionStorage.html")
        expected = ["key1",
                    "key2",
                    "value1",
                    "value3"]
        self.do_perform_test(caplog, sample, expected)

    def test_testSetInterval(self, caplog):
        sample   = os.path.join(self.misc_path, "testSetInterval.html")
        expected = ["[Window] Alert Text: Hello"]
        self.do_perform_test(caplog, sample, expected)

    def test_testText(self, caplog):
        sample   = os.path.join(self.misc_path, "testText.html")
        expected = ['<p id="p1">First line of paragraph.<br/> Some text added dynamically. </p>']
        self.do_perform_test(caplog, sample, expected)

    def test_testWindowOnload(self, caplog):
        sample   = os.path.join(self.misc_path, "testWindowOnload.html")
        expected = ["[Window] Alert Text: Fired"]
        self.do_perform_test(caplog, sample, expected)

    def test_test_click(self, caplog):
        sample   = os.path.join(self.misc_path, "test_click.html")
        expected = ["[window open redirection] about:blank -> https://www.antifork.org"]
        self.do_perform_test(caplog, sample, expected)

    def test_testInsertAdjacentHTML1(self, caplog):
        sample   = os.path.join(self.misc_path, "testInsertAdjacentHTML1.html")
        expected = ['<div id="five">five</div><div id="one">one</div>']
        self.do_perform_test(caplog, sample, expected)

    def test_testInsertAdjacentHTML2(self, caplog):
        sample   = os.path.join(self.misc_path, "testInsertAdjacentHTML2.html")
        expected = ['<div id="two"><div id="six">six</div>two</div>']
        self.do_perform_test(caplog, sample, expected)

    def test_testInsertAdjacentHTML3(self, caplog):
        sample   = os.path.join(self.misc_path, "testInsertAdjacentHTML3.html")
        expected = ['<div id="three">three<div id="seven">seven</div></div>']
        self.do_perform_test(caplog, sample, expected)

    def test_testInsertAdjacentHTML4(self, caplog):
        sample   = os.path.join(self.misc_path, "testInsertAdjacentHTML4.html")
        expected = ['<div id="four">four</div><div id="eight">eight</div>']
        self.do_perform_test(caplog, sample, expected)

    def test_testMicrosoftXMLHTTPEvent1(self, caplog):
        sample   = os.path.join(self.misc_path, "testMicrosoftXMLHTTPEvent1.html")
        expected = ["[Window] Alert Text: Request completed"]
        self.do_perform_test(caplog, sample, expected)

    def test_testMicrosoftXMLHTTPEvent2(self, caplog):
        sample   = os.path.join(self.misc_path, "testMicrosoftXMLHTTPEvent2.html")
        expected = ["[Window] Alert Text: Request completed"]
        self.do_perform_test(caplog, sample, expected)

    def test_testCurrentScript(self, caplog):
        sample   = os.path.join(self.misc_path, "testCurrentScript.html")
        expected = ["[Window] Alert Text: This page has scripts",
                    "[Window] Alert Text: text/javascript",
                    "[Window] Alert Text: Just a useless script"]
        self.do_perform_test(caplog, sample, expected)

    def test_testCCInterpreter(self, caplog):
        sample   = os.path.join(self.misc_path, "testCCInterpreter.html")
        expected = ['JavaScript version: 10',
                    'Running on the 32-bit version of Windows']
        self.do_perform_test(caplog, sample, expected)

    def test_testTextNode(self, caplog):
        sample   = os.path.join(self.misc_path, "testTextNode.html")
        expected = ['nodeName: #text',
                    'nodeType: 3',
                    'Object: [object Text]',
                    'nodeValue: Hello World',
                    'Length: 11',
                    'Substring(2,5): llo W',
                    'New nodeValue (replace): HelloAWorld',
                    'New nodeValue (delete 1): HelloWorld',
                    'Index error (delete 2)',
                    'New nodeValue (delete 3): Hello',
                    'New nodeValue (append): Hello Test',
                    'Index error (insert 1)',
                    'New nodeValue (insert 2): Hello New Test',
                    'New nodeValue (reset): Reset']

        self.do_perform_test(caplog, sample, expected)

    def test_testCommentNode(self, caplog):
        sample   = os.path.join(self.misc_path, "testCommentNode.html")
        expected = ['nodeName: #comment',
                    'nodeType: 8',
                    'Object: [object Comment]',
                    'nodeValue: <!--Hello World-->',
                    'Length: 18',
                    'Substring(2,5): --Hel',
                    'New nodeValue (replace): <!--HAllo World-->',
                    'New nodeValue (delete 1): <!--Hllo World-->',
                    'Index error (delete 2)',
                    'New nodeValue (delete 3): <!--H',
                    'New nodeValue (append): <!--H Test',
                    'Index error (insert 1)',
                    'New nodeValue (insert 2): <!--H New Test',
                    'New nodeValue (reset): Reset']

        self.do_perform_test(caplog, sample, expected)

    def test_testDOMImplementation(self, caplog):
        sample   = os.path.join(self.misc_path, "testDOMImplementation.html")
        expected = ["hasFeature('core'): true", ]

        self.do_perform_test(caplog, sample, expected)

    def test_testAttrNode(self, caplog):
        sample   = os.path.join(self.misc_path, "testAttrNode.html")
        expected = ['Object: [object Attr]',
                    'nodeName: test',
                    'nodeType: 2',
                    'nodeValue: foo',
                    'Length: undefined',
                    'New nodeValue: test2',
                    'Parent: null',
                    'Owner: null',
                    'Name: test',
                    'Specified: true',
                    'childNodes length: 0']

        self.do_perform_test(caplog, sample, expected)

    def test_testReplaceChild(self, caplog):
        sample   = os.path.join(self.misc_path, "testReplaceChild.html")
        expected = ["Alert Text: New child", ]

        self.do_perform_test(caplog, sample, expected)

    def test_testCookie(self, caplog):
        sample   = os.path.join(self.misc_path, "testCookie.html")
        expected = ["Alert Text: favorite_food=tripe; name=oeschger", ]

        self.do_perform_test(caplog, sample, expected)

    def test_testDocumentFragment1(self, caplog):
        sample   = os.path.join(self.misc_path, "testDocumentFragment1.html")
        expected = ["<div><p>Test</p></div>", ]

        self.do_perform_test(caplog, sample, expected)

    def test_testDocumentFragment2(self, caplog):
        sample   = os.path.join(self.misc_path, "testDocumentFragment2.html")
        expected = ["<div id=\"foobar\"><b>This is B</b></div>", ]

        self.do_perform_test(caplog, sample, expected)

    def test_testDocumentFragment3(self, caplog):
        sample   = os.path.join(self.misc_path, "testDocumentFragment3.html")
        expected = ["Alert Text: <div id=\"foo:bar\"></div>", ]

        self.do_perform_test(caplog, sample, expected)

    def test_testClassList1(self, caplog):
        sample   = os.path.join(self.misc_path, "testClassList1.html")
        expected = ['[Initial value] <div class="foo"></div>',
                    '[After remove and add] <div class="anotherclass"></div>',
                    '[Item] anotherclass',
                    '[Empty item] null',
                    '[Toggle visible] true',
                    '[After toggle] <div class="anotherclass"></div>']

        self.do_perform_test(caplog, sample, expected)

    def test_testClassList4(self, caplog):
        sample   = os.path.join(self.misc_path, "testClassList4.html")
        expected = ['[After remove and add] <div class="anotherclass"></div>', ]

        self.do_perform_test(caplog, sample, expected)

    def test_testDocumentType(self, caplog):
        sample   = os.path.join(self.misc_path, "testDocumentType.html")
        expected = ['Doctype: [object DocumentType]',
                    'Doctype name: html',
                    'Doctype nodeName: html',
                    'Doctype nodeType: 10',
                    'Doctype nodeValue: null',
                    'Doctype publicId: ',
                    'Doctype systemId: ',
                    'Doctype textContent: null']

        self.do_perform_test(caplog, sample, expected)
