"""
A script that extracts shellcode from PDF files

The script uses very basic shellcode extraction algorithm

Copyright (c) 1990-2010 Hex-Rays
ALL RIGHTS RESERVED.

v1.0 - initial version
"""

import re
import hashlib
import zlib
import binascii
import traceback

try:
    import idaapi
    from idc import *
    ida = True
except:
    ida = False

PDF_FILE = "log/downloads/pdf/%s.pdf"

class PDFAnalyzer:
    def __init__(self, sample):
        self.sample = sample

    def preparse_sample(self):
        sample = self.sample
        pattern = re.compile(r'(#\d{1}\S{1})')
        p = pattern.findall(sample)
        for entity in p:
            sample = re.sub(str(entity),
                            str(unichr(int(entity.split("#")[1], 16))),
                            sample)
        return sample

    def extract_shellcode(self, lines):
        """
        Tries to find shellcode inside JavaScript statements
        The seach algorithm is simple: it searchs for anything between
        unescape() if it encounters %u or %x it correctly decodes them to
        characters
        """
        p = 0
        shellcode = [] # accumulate shellcode
        while True:
            p = lines.find('unescape("', p)
            if p == -1:
                break
            e = lines.find(')', p)
            if e == -1:
                break
            expr = lines[p+9:e]
            data = []
            for i in xrange(0, len(expr)):
                if expr[i:i+2] == "%u":
                    i += 2
                    data.extend([chr(int(expr[i+2:i+4], 16)), chr(int(expr[i:i+2], 16))])
                    i += 4
                elif expr[i] == "%":
                    i += 1
                    data.append(int(expr[i:i+2], 16))
                    i += 2
            # advance the match pos
            p += 8
            shellcode.append("".join(data))
    
        # That's it
        return shellcode

    def find_obj(self, str, id, ver):
        """
        Given a PDF object id and version, we return the object declaration
        """
        stream = re.search('%d %d obj(.*?)endobj' % (id, ver), str, re.MULTILINE | re.DOTALL)
        if not stream:
            return None
        return str[stream.start(1):stream.end(1)]

    def find_js_ref_streams(self, str):
        """
        Find JavaScript objects and extract the referenced script object id/ver
        """
        o = []
        JS = []
        for r in re.finditer(r'<<(.+?)\/S\s*\/JavaScript(.+?)>>', str, re.MULTILINE | re.DOTALL):
            JS = [p for p in r.groups() if re.search(r'/JS', p)]
        for js in JS:
            for js_ref_stream in re.finditer('\/JS (\d+) (\d+) R', js):
                id  = int(js_ref_stream.group(1))
                ver = int(js_ref_stream.group(2))
                o.append([id, ver])
                print "[*] Extracted Javascript Referenced Stream Object: [%d, %d]" % (id, ver, ) 
        return o

    def find_embedded_js(self, str):
        """
        Find JavaScript objects and extract the embedded script
        """
        r = re.finditer('\/S\s*\/JavaScript\s*\/JS \((.+?)>>', str, re.MULTILINE | re.DOTALL)
        if not r:
            return None

        ret = []
        for js in r:
            print js
            p = str.rfind('obj', 0, js.start(1))
            if p == -1:
                return None

            scs = self.extract_shellcode(js.group(1))
            if not scs:
                return None

            t = str[p - min(20, len(str)): p + 3]
            obj = re.search('(\d+) (\d+) obj', t)
            if not obj:
                id, ver = 0
            else:
                id = int(obj.group(1))
                ver = int(obj.group(2))
            n = 0
            for sc in scs:
                n += 1
                ret.append([id, ver, n, sc])
        return ret
    
    def decompress_stream(self, str):
        """
        Given a gzipped stream object, it returns the decompressed contents. If
        the stream object is not compressed it is returned as it is.
        """
        m = re.search('stream\s*(.+?)\s*endstream', str, re.DOTALL | re.MULTILINE)
        if not m:
            return None

        if re.search('Filter(.+?)FlateDecode', str):
            try:
                r = zlib.decompress(m.group(1))
            except:
                traceback.print_exc()
                return None
        else:
            r = m.group(1)

        if re.search('ASCIIHexDecode', str):
             return self.ASCIIHexDecode(r)

        return r

    def ASCIIHexDecode(self, data):
        return binascii.unhexlify(''.join([c for c in data if c not in ' \t\n\r']).rstrip('>'))

    def read_whole_file(self, li):
        li.seek(0)
        return li.read(li.size())

    def extract_pdf_shellcode(self, buf):
        ret = []

        # find all JS stream references
        r = self.find_js_ref_streams(buf)
        for id, ver in r:
            # extract the JS stream object
            obj = self.find_obj(buf, id, ver)

            # decode the stream
            stream = self.decompress_stream(obj)

            # extract shell code
            scs = self.extract_shellcode(stream)
            i = 0
            for sc in scs:
                i += 1
                ret.append([id, ver, i, sc])

        # find all embedded JS
        r = self.find_embedded_js(buf)
        if r:
            ret.extend(r)

        return ret
    
    def store_sample(self):
        buf = self.sample
        h = hashlib.md5()
        h.update(buf)
        self.filename = PDF_FILE % (h.hexdigest(), )
        print "[*] Saving PDF file: %s" % (self.filename, )
        fd = open(self.filename, 'wb')
        fd.write(buf)
        fd.close()

    def run(self):
        samples = list()
        samples.append(self.sample)

        self.store_sample()
        print "[*] Starting PDF Analysis"
        try:
            parsed_sample = self.preparse_sample()
            samples.append(parsed_sample)
        except:
            pass

        for sample in samples:
            buf = sample

            # find all JS stream references
            r = self.find_js_ref_streams(buf)
            if not r:
                continue

            for id, ver in r:
                obj = self.find_obj(buf, id, ver)
        
                # extract the JS stream object
                objfile = '%s_obj_%d_%d.bin' % (self.filename, id, ver)
                print "[*] Saving Javascript Object Stream [%d, %d] (%s)" % (id, ver, objfile)
                f = file(objfile, 'wb')
                f.write(obj)
                f.close()

                # decode the stream
                stream = self.decompress_stream(obj)
                if not stream:
                    continue
                
                decfile = '%s_dec_%d_%d.bin' % (self.filename, id, ver)
                print "[*] Saving Decoded Javascript Object Stream [%d, %d] (%s)" % (id, ver, decfile)
                f = file(decfile, 'wb')
                f.write(stream)
                f.close()

                # extract shell code
                scs = self.extract_shellcode(stream)
                i = 0
                for sc in scs:
                    i += 1
                    f = file('%s_sh_%d_%d_%d.bin' % (self.filename, id, ver, i), 'wb')
                    f.write(sc)
                    f.close()

            break

