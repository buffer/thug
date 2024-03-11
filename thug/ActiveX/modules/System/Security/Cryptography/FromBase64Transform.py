import base64
import logging

log = logging.getLogger("Thug")


def TransformFinalBlock(self, buffer, offset, count):
    return bytes(base64.b64decode("".join(buffer[offset : offset + count])))
