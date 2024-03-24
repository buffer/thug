import logging

log = logging.getLogger("Thug")


def GetByteCount_2(self, chars):
    return len(chars.encode("utf-8"))


def GetBytes_4(self, chars):
    return list(chars)
