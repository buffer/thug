#!/usr/bin/env python
#
# SampleLogging.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

import os
import base64
import logging
import hashlib
import zipfile
import tempfile
import pefile
import ssdeep
import magic

log = logging.getLogger("Thug")


class SampleLogging:
    doc_mime_types = (
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    )

    rtf_mime_types = (
        'text/rtf',
        'application/rtf',
    )

    MB = 1024 * 1024

    MAX_CAB_FILE_SIZE = 32 * MB
    MAX_DOC_FILE_SIZE = 32 * MB
    MAX_ELF_FILE_SIZE = 32 * MB
    MAX_JAR_FILE_SIZE = 32 * MB
    MAX_PDF_FILE_SIZE = 32 * MB
    MAX_PE_FILE_SIZE  = 32 * MB
    MAX_RTF_FILE_SIZE = 32 * MB
    MAX_SWF_FILE_SIZE = 32 * MB

    def __init__(self):
        self.types = ('PE',
                      'ELF',
                      'PDF',
                      'JAR',
                      'SWF',
                      'DOC',
                      'RTF',
                      'CAB')

    def is_pe(self, data):
        if len(data) > self.MAX_PE_FILE_SIZE:
            return False # pragma: no cover

        try:
            pefile.PE(data = data, fast_load = True)
        except Exception: # pylint:disable=broad-except
            return False

        return True

    @staticmethod
    def get_imphash(data):
        try:
            pe = pefile.PE(data = data)
        except Exception: # pylint:disable=broad-except
            return None

        return pe.get_imphash()

    def is_pdf(self, data):
        if len(data) > self.MAX_PDF_FILE_SIZE:
            return False # pragma: no cover

        data = data.encode() if isinstance(data, str) else data
        return data[:1024].find(b'%PDF') != -1

    def is_elf(self, data):
        if len(data) > self.MAX_ELF_FILE_SIZE:
            return False # pragma: no cover

        data = data.encode() if isinstance(data, str) else data
        return data.startswith(b'\x7fELF')

    def is_jar(self, data):
        result = False

        if len(data) > self.MAX_JAR_FILE_SIZE:
            return result # pragma: no cover

        data = data.encode() if isinstance(data, str) else data

        fd, jar = tempfile.mkstemp()
        with open(jar, 'wb') as fd:
            fd.write(data)

        try:
            with zipfile.ZipFile(jar) as z:
                result = any(t.endswith('.class') for t in z.namelist())
        except Exception: # pylint:disable=broad-except
            pass

        os.remove(jar)
        return result

    def is_swf(self, data):
        if len(data) > self.MAX_SWF_FILE_SIZE:
            return False # pragma: no cover

        data = data.encode() if isinstance(data, str) else data
        return data.startswith(b'CWS') or data.startswith(b'FWS')

    def is_doc(self, data):
        if len(data) > self.MAX_DOC_FILE_SIZE:
            return False # pragma: no cover

        data = data.encode() if isinstance(data, str) else data
        return log.Magic.get_mime(data) in self.doc_mime_types

    def is_rtf(self, data):
        if len(data) > self.MAX_RTF_FILE_SIZE:
            return False # pragma: no cover

        return magic.from_buffer(data, mime = True) in self.rtf_mime_types

    def is_cab(self, data):
        if len(data) > self.MAX_CAB_FILE_SIZE:
            return False # pragma: no cover

        data = data.encode() if isinstance(data, str) else data
        return data.startswith(b'MSCF')

    def get_sample_type(self, data):
        for t in self.types:
            p = getattr(self, f'is_{t.lower()}', None)
            if p and p(data):
                return t

        return None

    def build_sample(self, data, url = None, sampletype = None):
        if not data:
            return None

        p = {}

        if sampletype:
            data = data.encode() if isinstance(data, str) else data
            p['type'] = sampletype
        else:
            p['type'] = self.get_sample_type(data)

        if p['type'] is None:
            return None

        p['md5']    = hashlib.md5(data).hexdigest() # nosec
        p['sha1']   = hashlib.sha1(data).hexdigest() # nosec
        p['sha256'] = hashlib.sha256(data).hexdigest()
        p['ssdeep'] = ssdeep.hash(data)

        if p['type'] in ('PE', ):
            imphash = self.get_imphash(data)
            if imphash:
                p['imphash'] = imphash

        if url:
            p['url'] = url

        p['data'] = base64.b64encode(data).decode()
        return p
