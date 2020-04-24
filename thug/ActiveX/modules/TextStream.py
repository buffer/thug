
import os
import hashlib
import string
import random
import errno
import logging

from thug.Magic.Magic import Magic

log = logging.getLogger("Thug")


class TextStream(object):
    def __init__(self):
        self.stream         = list()
        self._Line          = 1
        self._Column        = 1
        self._currentLine   = 1
        self._currentColumn = 1

    @property
    def Line(self):
        return self._Line

    @property
    def Column(self):
        return self._Column

    @property
    def AtEndOfLine(self):
        line = self.stream[self._currentLine - 1]
        return self._currentColumn >= len(line)

    @property
    def AtEndOfStream(self):
        if self._currentLine in (self._Line, ) and self._currentColumn in (self._Column - 1, ):
            return True

        return False

    def Read(self, characters):
        consume = characters

        result = ""

        while consume > 0:
            if self._currentLine > self._Line:
                break

            if self._currentLine == self._Line and self._currentColumn > self._Column: # pragma: no cover
                break

            line   = self.stream[self._currentLine - 1]
            eline  = line[self._currentColumn - 1:]
            length = min(len(eline), consume)

            result  += eline[:length]
            consume -= length

            if consume > 0: # pragma: no cover
                result  += '\n'
                consume -= 1

                self._currentLine  += 1
                self._currentColumn = 1
            else:
                self._currentColumn += length

        return result

    def ReadLine(self):
        if self._currentLine > self._Line:
            return ""

        result = self.stream[self._currentLine - 1]
        self._currentLine += 1
        self._currentColumn = 1
        return result

    def ReadAll(self):
        result = '\n'.join(self.stream)

        self._currentLine   = len(self.stream)
        self._currentColumn = len(self.stream[self._currentLine - 1])

        return result

    def Write(self, _string):
        _str_string = str(_string)
        if not _str_string:
            return

        sstring = _str_string.split('\n')

        if len(self.stream) == self._Line - 1:
            self.stream.append(str())

        self.stream[self._Line - 1] += sstring[0]
        self._Column += len(sstring[0])

        lines_no = len(sstring)
        if lines_no == 1:
            return

        for i in range(1, lines_no):
            self._Line += 1
            self.stream.append(str())
            self.stream[self._Line - 1] = sstring[i]
            self._Column += len(sstring[i])

    def WriteLine(self, _string):
        self.Write(str(_string) + '\n')
        self._Column = 1

    def WriteBlankLines(self, lines):
        self.Write(lines * '\n')
        self._Column = 1

    def Skip(self, characters):
        skip = characters

        while skip > 0:
            line  = self.stream[self._currentLine - 1]
            eline = line[self._currentColumn - 1:]

            if skip > len(eline) + 1: # pragma: no cover
                self._currentLine  += 1
                self._currentColumn = 1
            else:
                self._currentColumn += skip

            skip -= len(eline) + 1

    def SkipLine(self):
        self._currentLine += 1
        self._currentColumn = 1

    def Close(self):
        content = '\n'.join(self.stream)
        log.info(content)

        _content = content.encode() if isinstance(content, str) else content

        data = {
            'content' : content,
            'status'  : 200,
            'md5'     : hashlib.md5(_content).hexdigest(),
            'sha256'  : hashlib.sha256(_content).hexdigest(),
            'fsize'   : len(content),
            'ctype'   : 'textstream',
            'mtype'   : Magic(_content).get_mime(),
        }

        log.ThugLogging.log_location(log.ThugLogging.url, data)
        log.TextClassifier.classify(log.ThugLogging.url, content)

        if not log.ThugOpts.file_logging:
            return

        log_dir = os.path.join(log.ThugLogging.baseDir, "analysis", "textstream")

        try:
            os.makedirs(log_dir)
        except OSError as e: # pragma: no cover
            if e.errno == errno.EEXIST:
                pass
            else:
                raise

        filename = self._filename.split('\\')[-1] if '\\' in self._filename else self._filename
        if not filename: # pragma: no cover
            filename = ''.join(random.choice(string.lowercase) for i in range(8))

        log_file = os.path.join(log_dir, filename)

        with open(log_file, 'w') as fd:
            fd.write(content)
