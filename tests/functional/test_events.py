import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestEvents(object):
    thug_path = os.path.dirname(os.path.realpath(__file__)).split("thug")[0]
    misc_path = os.path.join(thug_path, "thug", "samples/Events")

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
        sample   = os.path.join(self.misc_path, "testDocumentEvent.html")
        expected = ['[object HTMLEvent]',
                    '[object MouseEvent]',
                    '[object MutationEvent]',
                    '[object StorageEvent]',
                    '[object UIEvent]']

        self.do_perform_test(caplog, sample, expected)

    def testMouseEvent_IE60(self, caplog):
        sample   = os.path.join(self.misc_path, "testMouseEvent.html")
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
        sample   = os.path.join(self.misc_path, "testMouseEvent.html")
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
        sample   = os.path.join(self.misc_path, "testMouseEvent.html")
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
        sample   = os.path.join(self.misc_path, "testMouseEvent.html")
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
        sample   = os.path.join(self.misc_path, "testMouseEvent.html")
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
        sample   = os.path.join(self.misc_path, "testStorageEvent.html")
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
        sample   = os.path.join(self.misc_path, "testMutationEvent.html")
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

    def test_testEvent2(self, caplog):
        sample   = os.path.join(self.misc_path, "testEvent2.html")
        expected = ['1. Div capture ran',
                    'Link capture ran - browser does not follow the specification',
                    '2. Link bubble ran (first listener)',
                    '2. Link bubble ran (second listener)',
                    '3. Div bubble ran']

        self.do_perform_test(caplog, sample, expected)
