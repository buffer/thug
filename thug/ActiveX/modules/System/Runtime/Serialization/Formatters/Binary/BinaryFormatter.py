import logging

log = logging.getLogger("Thug")

from thug.ActiveX.modules.System.Runtime.Delegate import Delegate


def Deserialize_2(self, buf):
    data = buf.stream.getvalue()
    return Delegate(data)
