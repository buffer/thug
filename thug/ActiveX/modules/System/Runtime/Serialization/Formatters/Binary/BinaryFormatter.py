import logging

from thug.ActiveX.modules.System.Runtime.Delegate import Delegate

log = logging.getLogger("Thug")


def Deserialize_2(self, buf):
    data = buf.stream.getvalue()
    return Delegate(data)
