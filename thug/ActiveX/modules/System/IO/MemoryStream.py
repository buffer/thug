import io
import logging

log = logging.getLogger("Thug")


def Write(self, buffer, offset=0, count=-1):
    log.ThugLogging.add_behavior_warn("[System.IO.MemoryStream] Write")

    buflen = count if count > -1 else len(buffer)
    bufdat = buffer[: buflen - 1]

    streamdata = self.stream.getvalue()
    data = f"{streamdata[:offset]}{bufdat}{streamdata[offset:]}"

    self.stream = io.BytesIO(data.encode())
    self.Position = len(data)
