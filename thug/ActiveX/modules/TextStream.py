
import os
import errno
import logging

log = logging.getLogger("Thug")

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


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
	sstring = _string.split('\n')

        if len(sstring) > 1:
	    self._Line  += len(sstring)
	    self._Column = len(sstring[-1]) + 1
        else:
            self._Column += len(_string)

        self.stream.write(_string)

    def WriteLine(self, string):
        self.Write(string + '\n')

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

        log.TextClassifier.classify("{} (file: {})".format(log.ThugLogging.url, self._filename), content)

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
        log_file = os.path.join(log_dir, filename)

        with open(log_file, 'wb') as fd:
            fd.write(content)
