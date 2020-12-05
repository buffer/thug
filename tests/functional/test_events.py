import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestEvents(object):
    cwd_path  = os.path.dirname(os.path.realpath(__file__))
    event_path = os.path.join(cwd_path, os.pardir, "samples/Events")

    def do_perform_test(self, caplog, sample, expected, events = '', useragent = 'win7ie90'):
        thug = ThugAPI()

        thug.set_useragent(useragent)
        thug.set_events(events)
        thug.disable_cert_logging()
        thug.set_features_logging()
        thug.log_init(sample)
        thug.run_local(sample)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_testDocumentEvent(self, caplog):
        sample   = os.path.join(self.event_path, "testDocumentEvent.html")
        expected = ['[object HTMLEvent]',
                    '[object MouseEvent]',
                    '[object MutationEvent]',
                    '[object StorageEvent]',
                    '[object UIEvent]']

        self.do_perform_test(caplog, sample, expected)

    def testMouseEvent_IE60(self, caplog):
        sample   = os.path.join(self.event_path, "testMouseEvent.html")
        expected = ['[object MouseEvent]',
                    'type: click',
                    'target: null',
                    'bubbles: false',
                    'cancelable: false',
                    'screenX: 0',
                    'screenY: 0',
                    'clientX: 0',
                    'clientY: 0',
                    'ctlrKey: false',
                    'altKey: false',
                    'shiftKey: false',
                    'metaKey: false',
                    'button: 0',
                    'relatedTarget: null',
                    'detail: 0',
                    'view: [object Window]',
                    'defaultPrevented: undefined']

        self.do_perform_test(caplog, sample, expected, useragent = 'winxpie60')

    def testMouseEvent_IE90(self, caplog):
        sample   = os.path.join(self.event_path, "testMouseEvent.html")
        expected = ['[object MouseEvent]',
                    'type: click',
                    'target: null',
                    'bubbles: false',
                    'cancelable: false',
                    'screenX: 0',
                    'screenY: 0',
                    'clientX: 0',
                    'clientY: 0',
                    'ctlrKey: false',
                    'altKey: false',
                    'shiftKey: false',
                    'metaKey: false',
                    'button: 0',
                    'relatedTarget: null',
                    'detail: 0',
                    'view: [object Window]',
                    'defaultPrevented: false']

        self.do_perform_test(caplog, sample, expected, useragent = 'win7ie90')

    def testMouseEvent_Chrome(self, caplog):
        sample   = os.path.join(self.event_path, "testMouseEvent.html")
        expected = ['[object MouseEvent]',
                    'type: click',
                    'target: null',
                    'bubbles: false',
                    'cancelable: false',
                    'screenX: 0',
                    'screenY: 0',
                    'clientX: 0',
                    'clientY: 0',
                    'ctlrKey: false',
                    'altKey: false',
                    'shiftKey: false',
                    'metaKey: false',
                    'button: 0',
                    'relatedTarget: null',
                    'detail: 0',
                    'view: [object Window]',
                    'defaultPrevented: false']

        self.do_perform_test(caplog, sample, expected, useragent = 'win7chrome49')

    def testMouseEvent_Safari(self, caplog):
        sample   = os.path.join(self.event_path, "testMouseEvent.html")
        expected = ['[object MouseEvent]',
                    'type: click',
                    'target: null',
                    'bubbles: false',
                    'cancelable: false',
                    'screenX: 0',
                    'screenY: 0',
                    'clientX: 0',
                    'clientY: 0',
                    'ctlrKey: false',
                    'altKey: false',
                    'shiftKey: false',
                    'metaKey: false',
                    'button: 0',
                    'relatedTarget: null',
                    'detail: 0',
                    'view: [object Window]',
                    'defaultPrevented: false']

        self.do_perform_test(caplog, sample, expected, useragent = 'win7safari5')

    def testMouseEvent_Firefox(self, caplog):
        sample   = os.path.join(self.event_path, "testMouseEvent.html")
        expected = ['[object MouseEvent]',
                    'type: click',
                    'target: null',
                    'bubbles: false',
                    'cancelable: false',
                    'screenX: 0',
                    'screenY: 0',
                    'clientX: 0',
                    'clientY: 0',
                    'ctlrKey: false',
                    'altKey: false',
                    'shiftKey: false',
                    'metaKey: false',
                    'button: 0',
                    'relatedTarget: null',
                    'detail: 0',
                    'view: [object Window]',
                    'defaultPrevented: false']

        self.do_perform_test(caplog, sample, expected, useragent = 'linuxfirefox40')

    def testStorageEvent(self, caplog):
        sample   = os.path.join(self.event_path, "testStorageEvent.html")
        expected = ['[object StorageEvent]',
                    'type: storage',
                    'target: null',
                    'bubbles: false',
                    'cancelable: false',
                    'key: key',
                    'oldValue: oldValue',
                    'newValue: newValue',
                    'url: http://www.example.com',
                    'storageArea: [object SessionStorage]']

        self.do_perform_test(caplog, sample, expected)

    def testMutationEvent(self, caplog):
        sample   = os.path.join(self.event_path, "testMutationEvent.html")
        expected = ['[object MutationEvent]',
                    'type: DOMAttrModified',
                    'target: null',
                    'bubbles: true',
                    'cancelable: true',
                    'relatedNode: [object Attr]',
                    'prevValue: null',
                    'newValue: foobar',
                    'attrName: value',
                    'attrChange: 1']

        self.do_perform_test(caplog, sample, expected)

    def test_testEventException(self, caplog):
        sample   = os.path.join(self.event_path, "testEventException.html")
        expected = ['Error', ]

        self.do_perform_test(caplog, sample, expected)

    def test_testMouseMove(self, caplog):
        sample   = os.path.join(self.event_path, "testMouseMove.html")
        expected = ['mousemove event detected', ]

        self.do_perform_test(caplog, sample, expected)

    def test_testEvent1(self, caplog):
        sample   = os.path.join(self.event_path, "testEvent1.html")
        expected = ['add',
                    '[object HTMLParagraphElement]']

        self.do_perform_test(caplog, sample, expected)

    def test_testEvent2(self, caplog):
        sample   = os.path.join(self.event_path, "testEvent2.html")
        expected = ['1. Div capture ran',
                    'Link capture ran - browser does not follow the specification',
                    '2. Link bubble ran (first listener)',
                    '2. Link bubble ran (second listener)',
                    '3. Div bubble ran']

        self.do_perform_test(caplog, sample, expected)

    def test_testEvent4(self, caplog):
        sample   = os.path.join(self.event_path, "testEvent4.html")
        expected = ['add',
                    '[object HTMLParagraphElement]']

        self.do_perform_test(caplog, sample, expected, useragent = 'winxpie60')

    def test_testEvent7(self, caplog):
        sample   = os.path.join(self.event_path, "testEvent7.html")
        expected = ['foobar', ]

        self.do_perform_test(caplog, sample, expected, events = 'click')

    def test_testEvent8(self, caplog):
        sample   = os.path.join(self.event_path, "testEvent8.html")
        expected = ['Clicked',
                    'foobar', ]

        self.do_perform_test(caplog, sample, expected, events = 'click')

    def test_testEvent11(self, caplog):
        sample   = os.path.join(self.event_path, "testEvent11.html")
        expected = ['[object Event]',
                    '[object Window]',
                    'clicked',
                    'clicked 2']

        self.do_perform_test(caplog, sample, expected, events = 'click')

    def test_testEvent12(self, caplog):
        sample   = os.path.join(self.event_path, "testEvent12.html")
        expected = ['You should see me two times',
                    'First click']

        self.do_perform_test(caplog, sample, expected, events = 'click', useragent = 'winxpie60')

    def test_testEvent17(self, caplog):
        sample   = os.path.join(self.event_path, "testEvent17.html")
        expected = ['clicked', ]

        self.do_perform_test(caplog, sample, expected, events = 'click', useragent = 'winxpie60')

    def test_testEvent18(self, caplog):
        sample   = os.path.join(self.event_path, "testEvent18.html")
        expected = ['clicked', ]

        self.do_perform_test(caplog, sample, expected, events = 'click')
