import logging

log = logging.getLogger("Thug")


def EncodeScriptFile(self, strExt, byte_stream, cFlags, bstrDefaultLang):
    msg = f'[Scripting.Encoder ActiveX] EncodeScriptFile("{strExt}", "{byte_stream}", {cFlags}, "{bstrDefaultLang}")'
    log.ThugLogging.add_behavior_warn(msg)
    return byte_stream
