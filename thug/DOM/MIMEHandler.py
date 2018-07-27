#!/usr/bin/env python
#
# MIMEHandler.py
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
import logging
import zipfile
import tempfile
import rarfile
from six import StringIO
import bs4 as BeautifulSoup

log = logging.getLogger("Thug")


class MIMEHandler(dict):
    """
        MIMEHandler class is meant to allow registering MIME handlers the
        same way a real browser would do.

        The default handling for almost all Content-Types is to not further
        processing the downloaded content and this can be done by returning
        True from the Content-Type handler. The method `passthrough' is the
        default handler associated to almost all Content-Types with the few
        exceptions defined in the method `register_empty_handlers'.

        Two ways actually exist for further processing a downloaded content.
        The first one is returning False from the the Content-Type handler.
        The second one is having a None Content-Type handler which turns to
        be quite useful when an unknown Content-Type is served. In such case
        the __missing__ method will return None (thus enabling further content
        processing) and log the unknown Content-Type for convenience.

        This design is quite flexible because i.e. you can decide to instantiate
        your own PDF analysis system really quickly by simply defining a new
        application/pdf Content-Type handler.
    """
    mimetypes = ("application/download",
                 "application/envoy",
                 "application/exe",
                 "application/fractals",
                 "application/futuresplash",
                 "application/internet-property-stream",
                 "application/java-archive",
                 "application/javascript",
                 "application/mac-binhex40",
                 "application/msword",
                 "application/octet-stream",
                 "application/oda",
                 "application/olescript",
                 "application/pdf",
                 "application/pics-rules",
                 "application/pkcs10",
                 "application/pkix-crl",
                 "application/postscript",
                 "application/rar",
                 "application/rtf",
                 "application/set-payment-initiation",
                 "application/set-registration-initiation",
                 "application/vnd.android.package-archive",
                 "application/vnd.ms-excel",
                 "application/vnd.ms-outlook",
                 "application/vnd.ms-pkicertstore",
                 "application/vnd.ms-pkiseccat",
                 "application/vnd.ms-pkistl",
                 "application/vnd.ms-powerpoint",
                 "application/vnd.ms-project",
                 "application/vnd.ms-works",
                 "application/winhlp",
                 "application/x-bcpio",
                 "application/x-bzip2",
                 "application/x-cdf",
                 "application/x-chrome-extension",
                 "application/x-compress",
                 "application/x-compressed",
                 "application/x-cpio",
                 "application/x-csh",
                 "application/x-director",
                 "application/x-dosexec",
                 "application/x-dvi",
                 "application/x-gtar",
                 "application/x-gzip",
                 "application/x-hdf",
                 "application/x-internet-signup",
                 "application/x-iphone",
                 "application/x-java-jnlp-file",
                 "application/x-javascript",
                 "application/x-latex",
                 "application/x-msaccess",
                 "application/x-mscardfile",
                 "application/x-msclip",
                 "application/x-msdos-program",
                 "application/x-msdownload",
                 "application/x-msmediaview",
                 "application/x-msmetafile",
                 "application/x-msmoney",
                 "application/x-mspublisher",
                 "application/x-msschedule",
                 "application/x-msterminal",
                 "application/x-mswrite",
                 "application/x-netcdf",
                 "application/x-perfmon",
                 "application/x-pkcs12",
                 "application/x-pkcs7-certificates",
                 "application/x-pkcs7-certreqresp",
                 "application/x-pkcs7-mime",
                 "application/x-pkcs7-signature",
                 "application/x-rar-compressed",
                 "application/x-sh",
                 "application/x-shar",
                 "application/x-shockwave-flash",
                 "application/x-silverlight-2",
                 "application/x-stuffit",
                 "application/x-sv4cpio",
                 "application/x-sv4crc",
                 "application/x-tar",
                 "application/x-tcl",
                 "application/x-tex",
                 "application/x-texinfo",
                 "application/x-troff",
                 "application/x-troff-man",
                 "application/x-troff-me",
                 "application/x-troff-ms",
                 "application/x-ustar",
                 "application/x-wais-source",
                 "application/x-x509-ca-cert",
                 "application/x-xpinstall",
                 "application/x-zip-compressed",
                 "application/ynd.ms-pkipko",
                 "application/zip",
                 "audio/basic",
                 "audio/mid",
                 "audio/mpeg",
                 "audio/x-aiff",
                 "audio/x-mpegurl",
                 "audio/x-ms-wma",
                 "audio/x-pn-realaudio",
                 "audio/x-wav",
                 "image/bmp",
                 "image/bmpimage/x-bmp",
                 "image/cis-cod",
                 "image/gif",
                 "image/ief",
                 "image/jpeg",
                 "image/pipeg",
                 "image/png",
                 "image/svg+xml",
                 "image/tiff",
                 "image/x-cmu-raster",
                 "image/x-cmx",
                 "image/x-icon",
                 "image/x-portable-anymap",
                 "image/x-portable-bitmap",
                 "image/x-portable-graymap",
                 "image/x-portable-pixmap",
                 "image/x-rgb",
                 "image/x-xbitmap",
                 "image/x-xpixmap",
                 "image/x-xwindowdump",
                 "message/rfc822",
                 "text/css",
                 "text/h323",
                 "text/html",
                 "text/iuls",
                 "text/javascript",
                 "text/plain",
                 "text/richtext",
                 "text/scriptlet",
                 "text/tab-separated-values",
                 "text/vnd.wap.wml",
                 "text/webviewhtml",
                 "text/x-component",
                 "text/x-setext",
                 "text/x-vcard",
                 "video/mpeg",
                 "video/quicktime",
                 "video/x-la-asf",
                 "video/x-ms-asf",
                 "video/x-msvideo",
                 "video/x-sgi-movie",
                 "x-world/x-vrml")

    def __missing__(self, key):
        _key = key.split(';')[0].strip()
        if _key in self:
            return self[_key]

        log.warning("[MIMEHandler] Unknown MIME Type: %s", key)
        return self.passthrough

    def __init__(self):
        for mimetype in self.mimetypes:
            self[mimetype] = self.passthrough

        self.handlers = list()

        self.register_empty_handlers()
        self.register_fallback_handlers()
        self.register_zip_handlers()
        self.register_rar_handlers()
        self.register_java_jnlp_handlers()
        self.register_json_handlers()

    def register_empty_handlers(self):
        self['application/hta']          = None
        self['application/javascript']   = None
        self['application/x-javascript'] = None
        self['text/css']                 = None
        self['text/html']                = None
        self['text/javascript']          = None

    def register_fallback_handlers(self):
        self['text/plain'] = self.handle_fallback

    def register_handler(self, mimetype, handler):
        self[mimetype] = handler
        self.handlers.append(handler)

    def register_zip_handlers(self):
        self.register_handler('application/zip', self.handle_zip)

    def register_rar_handlers(self):
        self.register_handler('application/x-rar-compressed', self.handle_rar)

    def register_java_jnlp_handlers(self):
        self['application/x-java-jnlp-file'] = self.handle_java_jnlp

    def register_json_handlers(self):
        self['application/json'] = self.handle_json

    def handle_fallback(self, url, content):
        for handler in self.handlers:
            try:
                if handler(url, content):
                    return True
            except Exception:
                pass

        return False

    def handle_zip(self, url, content):
        fp = StringIO(content)
        if not zipfile.is_zipfile(fp):
            return False

        try:
            zipdata = zipfile.ZipFile(fp)
        except Exception:
            return False

        for filename in zipdata.namelist():
            try:
                data = zipdata.read(filename)
            except Exception:
                continue

            if filename.lower().endswith('.js'):
                self.window.evalScript(data)

            sample = log.ThugLogging.log_file(data, url)
            if sample is None:
                continue

            try:
                md5 = sample['md5']
            except Exception:
                continue

            unzipped = os.path.join(log.ThugLogging.baseDir, 'unzipped')
            log.ThugLogging.store_content(unzipped, md5, data)

        return True

    def handle_rar(self, url, content):
        fd, rfile = tempfile.mkstemp()
        with open(rfile, 'wb') as fd:
            fd.write(content)

        try:
            rardata = rarfile.RarFile(rfile)
        except Exception:
            os.remove(rfile)
            return False

        for filename in rardata.namelist():
            try:
                data = rardata.read(filename)
            except Exception:
                continue

            sample = log.ThugLogging.log_file(data, url)
            if sample is None:
                continue

            try:
                md5 = sample['md5']
            except Exception:
                continue

            unzipped = os.path.join(log.ThugLogging.baseDir, 'unzipped')
            log.ThugLogging.store_content(unzipped, md5, data)

        os.remove(rfile)
        return True

    @property
    def javaWebStartUserAgent(self):
        javaplugin = log.ThugVulnModules._javaplugin.split('.')
        last = javaplugin.pop()
        version = '%s_%s' % ('.'.join(javaplugin), last)
        return "JNLP/6.0 javaws/%s (b04) Java/%s" % (version, version, )

    def handle_java_jnlp(self, url, data):
        headers = dict()
        headers['Connection'] = 'keep-alive'

        try:
            soup = BeautifulSoup.BeautifulSoup(data, "lxml")
        except Exception:
            return

        jnlp = soup.find("jnlp")
        if jnlp is None:
            return

        codebase = jnlp.attrs['codebase'] if 'codebase' in jnlp.attrs else ''

        log.ThugLogging.add_behavior_warn(description = '[JNLP Detected]', method = 'Dynamic Analysis')

        jars = soup.find_all("jar")
        if not jars:
            return

        headers['User-Agent'] = self.javaWebStartUserAgent

        for jar in jars:
            try:
                url = "%s%s" % (codebase, jar.attrs['href'], )
                self.window._navigator.fetch(url, headers = headers, redirect_type = "JNLP")
            except Exception:
                pass

    def handle_json(self, url, data):
        headers = dict()
        headers['Connection'] = 'keep-alive'

        try:
            content = json.loads(data)
        except Exception:
            return

        for key in content.keys():
            if key.lower() in ('@content.downloadurl', ):
                try:
                    self.window._navigator.fetch(content[key], headers = headers, redirect_type = "JSON")
                except Exception:
                    pass

    def passthrough(self, url, data):
        """
        The method passthrough is the default handler associated to
        almost all Content-Types with the few exceptions defined in
        register_empty_handlers.
        """
        return True

    def get_handler(self, key):
        return self[key.split(';')[0]]
