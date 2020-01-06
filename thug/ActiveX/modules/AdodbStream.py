from io import BytesIO

import logging
from thug.Magic.Magic import Magic

log = logging.getLogger("Thug")


def getSize(self):
    fobject = getattr(self, 'fobject', None)
    content = self.fobject.getvalue() if fobject else str()
    return len(content)


def open(self):  # pylint:disable=redefined-builtin
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] open")
    self.fobject = BytesIO()


def Read(self, length = -1):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] Read")

    fobject = getattr(self, 'fobject', None)
    content = self.fobject.getvalue() if fobject else str()

    if length > 0:
        length = min(length, len(content))

    return content[self.position:length] if length > 0 else content[self.position:]


def Write(self, s):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] Write")
    self.fobject.write(s.encode())


def SaveToFile(self, filename, opt = 0):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] SaveToFile(%s, %s)" % (filename, opt, ))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Adodb.Stream ActiveX",
                                      "SaveToFile",
                                      data = {
                                                "file": filename
                                             },
                                      forward = False)

    content = self.fobject.getvalue()
    mtype   = Magic(content).get_mime()

    log.ThugLogging.log_file(content, url = filename, sampletype = mtype)
    self._files[filename] = content


def LoadFromFile(self, filename):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] LoadFromFile(%s)" % (filename, ))
    if filename not in self._files:
        raise TypeError()

    self._current = filename


def ReadText(self, NumChars = -1):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] ReadText")

    if NumChars == -1:
        return self._files[self._current][self.position:]

    return self._files[self._current][self.position:self.position + NumChars]


def WriteText(self, data, options = None):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] WriteText(%s)" % (data, ))
    self.fobject.write(data.encode())


def Close(self):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] Close")
    self.fobject.close()


def setPosition(self, pos):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] Changed position in fileobject to: (%s)" % (pos, ))
    self.__dict__['position'] = pos
    self.fobject.seek(pos)
