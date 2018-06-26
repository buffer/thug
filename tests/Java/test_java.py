from thug.Java.java import java
from thug.Java.lang import lang


def test_java():
    obj_java = java()
    assert isinstance(obj_java.lang, lang)
