from thug.DOM.JSClass import JSClass


class JSClassTest(JSClass):
    def __init__(self, value):
        self.value = value


class TestJSClass(object):
    def getter(self):
        return "foobar"

    def test_jsclass_1(self):
        test1 = JSClassTest("test1")

        assert test1.value == "test1"
        assert str(test1.prototype) == "[object JSClassPrototype]"
        assert "[native code]" in str(test1.constructor)

        test1.__defineGetter__("anothervalue", self.getter)
        assert test1.anothervalue == "foobar"

        test2 = test1.constructor("test2")
        assert test2.value == "test2"
