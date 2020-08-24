import logging

log = logging.getLogger("Thug")


def EncodeScriptFile(self, strExt, byte_stream, cFlags, bstrDefaultLang):
    msg = '[Scripting.Encoder ActiveX] EncodeScriptFile("{}", "{}", {}, "{}")'.format(strExt,
                                                                                      byte_stream,
                                                                                      cFlags,
                                                                                      bstrDefaultLang)

    log.ThugLogging.add_behavior_warn(msg)
    return byte_stream
