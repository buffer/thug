import logging

from thug.ActiveX.modules.System.Runtime.Delegate import Delegate

log = logging.getLogger("Thug")


def Deserialize_2(self, buf):
    log.ThugLogging.add_behavior_warn("[System.Runtime.Serialization.Formatters.Binary.BinaryFormatter] Deserialize_2")

    data = buf.stream.getvalue()
    return Delegate(data)
