import base64
import logging

log = logging.getLogger("Thug")


def TransformFinalBlock(self, buffer, offset, count):
    log.ThugLogging.add_behavior_warn("[System.Security.Cryptography.FromBase64ToTransform] TransformFinalBlock")
    return bytes(base64.b64decode("".join(buffer[offset : offset + count])))
