from thug.Java.lang import lang
from thug.Java.System import System


def test_lang():
    obj_lang = lang()
    assert isinstance(obj_lang.System, System)
