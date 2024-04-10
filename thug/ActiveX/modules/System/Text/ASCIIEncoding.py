import logging

log = logging.getLogger("Thug")


def GetByteCount_2(self, chars):
    count = len(chars.encode("utf-8"))
    log.ThugLogging.add_behavior_warn(
        f"[System.Text.ASCIIEncoding] GetByteCount_2 count = {count}"
    )
    return count


def GetBytes_4(self, chars):
    log.ThugLogging.add_behavior_warn("[System.Text.ASCIIEncoding] GetBytes_4")
    return list(chars)
