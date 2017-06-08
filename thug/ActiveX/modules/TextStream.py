
import os
import hashlib
import string
import random
import errno
import logging

from six import StringIO
from thug.Magic.Magic import Magic

log = logging.getLogger("Thug")


class TextStream(object):
    def __init__(self):
        self.stream = StringIO()
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
        sstream = self.stream.getvalue().split('\n')
        line    = sstream[self._currentLine]

        if len(line[self._currentColumn:]) == 0:
            return True

        return False

    @property
    def AtEndOfStream(self):
        if self._currentLine == self._Line and self._currentColumn == self._Column:
            return True

        return False

    def Read(self, characters):
        consume = characters
        sstream = self.stream.getvalue().split('\n')

        result = ""

        while consume > 0:
            line   = sstream[self._currentLine]
            eline  = line[self._currentColumn:]
            length = min(len(eline), consume)

            result  += eline[:length]
            consume -= length

            if consume > 0:
                self._currentLine  += 1
                self._currentColumn = 1
            else:
                self._currentColumn += length

        return result

    def ReadLine(self):
        sstream = self.stream.getvalue().split('\n')
        result  = sstream[self._currentLine]
        self._currentLine += 1
        return result

    def ReadAll(self):
        return self.stream.getvalue()

    def Write(self, _string):
        _str_string = str(_string)
        sstring     = _str_string.split('\n')

        if len(sstring) > 1:
            self._Line  += len(sstring)
            self._Column = len(sstring[-1]) + 1
        else:
            self._Column += len(_str_string)

        self.stream.write(_str_string)

    def WriteLine(self, string):
        self.Write(str(string) + '\n')

    def WriteBlankLines(self, lines):
        self.Write(lines * '\n')

    def Skip(self, characters):
        skip    = characters
        sstream = self.stream.getvalue().split('\n')

        while skip > 0:
            line  = sstream[self._currentLine]
            eline = line[self._currentColumn:]

            if skip > len(eline):
                self._currentLine  += 1
                self._currentColumn = 1
                skip -= len(eline)
            else:
                self._currentColumn += skip

    def SkipLine(self):
        self._currentLine += 1

    def Close(self):
        content = self.stream.getvalue()
        log.info(content)

        data = {
            'content' : content,
            'status'  : 200,
            'md5'     : hashlib.md5(content).hexdigest(),
            'sha256'  : hashlib.sha256(content).hexdigest(),
            'fsize'   : len(content),
            'ctype'   : 'textstream',
            'mtype'   : Magic(content).get_mime(),
        }

        log.ThugLogging.log_location(log.ThugLogging.url, data)
        log.TextClassifier.classify(log.ThugLogging.url, content)

        if not log.ThugOpts.file_logging:
            return

        log_dir = os.path.join(log.ThugLogging.baseDir, "analysis", "textstream")

        try:
            os.makedirs(log_dir)
        except OSError as e:
            if e.errno == errno.EEXIST:
                pass
            else:
                raise

        filename = self._filename.split('\\')[-1] if '\\' in self._filename else self._filename
        if not filename:
            filename = ''.join(random.choice(string.lowercase) for i in range(8))

        log_file = os.path.join(log_dir, filename)
        with open(log_file, 'wb') as fd:
            fd.write(content)
