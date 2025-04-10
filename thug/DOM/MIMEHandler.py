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
import io
import types
import operator
import json
import logging
import zipfile
import tempfile
import bs4
import rarfile

OCR_ENABLED = True

try:
    from PIL import Image
    import pytesseract
except ImportError:  # pragma: no cover
    OCR_ENABLED = False


log = logging.getLogger("Thug")

MIMEHANDLER_PYHOOKS_NONE = 0
MIMEHANDLER_PYHOOKS_REQUIRED = 1
MIMEHANDLER_PYHOOKS_DONE = 2


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

    MB = 1024 * 1024

    MIN_ZIP_FILE_SIZE = 32
    MAX_ZIP_FILE_SIZE = 32 * MB
    MIN_RAR_FILE_SIZE = 32
    MAX_RAR_FILE_SIZE = 32 * MB
    MIN_IMG_FILE_SIZE = 32

    mimetypes = (
        "application/atom+xml",
        "application/download",
        "application/envoy",
        "application/exe",
        "application/fractals",
        "application/futuresplash",
        "application/internet-property-stream",
        "application/java-archive",
        "application/mac-binhex40",
        "application/msword",
        "application/oda",
        "application/olescript",
        "application/pdf",
        "application/pics-rules",
        "application/pkcs10",
        "application/pkix-crl",
        "application/postscript",
        "application/rss+xml",
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
        "application/x-empty",
        "application/x-executable",
        "application/x-gtar",
        "application/x-gzip",
        "application/x-hdf",
        "application/x-internet-signup",
        "application/x-iphone",
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
        "audio/basic",
        "audio/mid",
        "audio/mpeg",
        "audio/x-aiff",
        "audio/x-mpegurl",
        "audio/x-ms-wma",
        "audio/x-pn-realaudio",
        "audio/x-wav",
        "image/bmpimage/x-bmp",
        "image/cis-cod",
        "image/ief",
        "image/pipeg",
        "image/svg+xml",
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
        "text/h323",
        "text/iuls",
        "text/richtext",
        "text/scriptlet",
        "text/tab-separated-values",
        "text/vnd.wap.wml",
        "text/webviewhtml",
        "text/xml",
        "text/x-component",
        "text/x-setext",
        "text/x-vcard",
        "video/mp4",
        "video/mpeg",
        "video/quicktime",
        "video/x-la-asf",
        "video/x-ms-asf",
        "video/x-msvideo",
        "video/x-sgi-movie",
        "x-world/x-vrml",
    )

    def __missing__(self, key):
        _key = key.split(";")[0].strip()
        if _key in self:  # pragma: no cover
            return self[_key]

        log.warning("[MIMEHandler] Unknown MIME Type: %s", key)
        return self.passthrough

    def __init__(self):
        super().__init__()

        self.mimehandler_pyhooks = MIMEHANDLER_PYHOOKS_NONE

        for mimetype in self.mimetypes:
            self[mimetype] = self.passthrough

        self.handlers = []

        self.register_empty_handlers()
        self.register_fallback_handlers()
        self.register_zip_handlers()
        self.register_rar_handlers()
        self.register_java_jnlp_handlers()
        self.register_json_handlers()
        self.register_image_handlers()

    def init_pyhooks(self):
        self.mimehandler_pyhooks = MIMEHANDLER_PYHOOKS_DONE

        hooks = log.PyHooks.get("MIMEHandler", None)
        if hooks is None:
            return

        get_method_function = operator.attrgetter("__func__")
        get_method_self = operator.attrgetter("__self__")

        for label, hook in hooks.items():
            name = f"{label}_hook"
            _hook = get_method_function(hook) if get_method_self(hook) else hook
            method = types.MethodType(_hook, MIMEHandler)
            setattr(self, name, method)

        hook = getattr(self, "handle_image_hook", None)
        self.image_hook_enabled = hook is not None

    def register_empty_handlers(self):
        self["application/hta"] = None
        self["application/javascript"] = None
        self["application/x-javascript"] = None
        self["text/css"] = None
        self["text/html"] = None
        self["text/javascript"] = None

    def register_fallback_handlers(self):
        self["text/plain"] = self.handle_fallback
        self["application/octet-stream"] = self.handle_fallback

    def register_handler(self, mimetype, handler):
        self[mimetype] = handler
        self.handlers.append(handler)

    def register_zip_handlers(self):
        self.register_handler("application/zip", self.handle_zip)

    def register_rar_handlers(self):
        self.register_handler("application/rar", self.handle_rar)
        self.register_handler("application/x-rar-compressed", self.handle_rar)

    def register_java_jnlp_handlers(self):
        self["application/x-java-jnlp-file"] = self.handle_java_jnlp

    def register_json_handlers(self):
        self["application/json"] = self.handle_json

    def register_image_handlers(self):
        self.image_ocr_enabled = OCR_ENABLED
        self.image_hook_enabled = False
        self.mimehandler_pyhooks = MIMEHANDLER_PYHOOKS_REQUIRED

        self["image/bmp"] = self.handle_image
        self["image/gif"] = self.handle_image
        self["image/jpeg"] = self.handle_image
        self["image/png"] = self.handle_image
        self["image/svg+xml"] = self.handle_svg_xml
        self["image/tiff"] = self.handle_image

    def handle_fallback(self, url, content):
        for handler in self.handlers:
            try:
                if handler(url, content):
                    return True
            except Exception:  # pragma: no cover,pylint:disable=broad-except
                pass

        return False

    def handle_image(self, url, content):
        if not log.ThugOpts.image_processing:
            return False  # pragma: no cover

        if not self.image_ocr_enabled and not self.image_hook_enabled:
            return False  # pragma: no cover

        if len(content) < self.MIN_IMG_FILE_SIZE:
            return False  # pragma: no cover

        if self.image_ocr_enabled:
            self.perform_ocr_analysis(url, content)

        if self.image_hook_enabled:
            hook = getattr(self, "handle_image_hook")
            hook(
                (
                    url,
                    content,
                )
            )

        return True

    def do_perform_ocr_analysis(self, url, img):
        try:
            ocr_result = pytesseract.image_to_string(img)
            if ocr_result:
                log.ThugLogging.log_image_ocr(url, ocr_result)
                log.ImageClassifier.classify(url, ocr_result)
        except Exception as e:  # pragma: no cover,pylint:disable=broad-except
            log.warning("[OCR] Error: %s", str(e))
            return False

        return True

    def perform_ocr_analysis(self, url, content):
        try:
            fp = io.BytesIO(content)
            img = Image.open(fp)
        except Exception as e:  # pragma: no cover,pylint:disable=broad-except
            log.warning("[OCR] Error: %s", str(e))
            return

        if not self.do_perform_ocr_analysis(url, img):
            self.do_perform_ocr_analysis(url, img.convert())  # pragma: no cover

    def handle_zip(self, url, content):
        if isinstance(content, list):
            content = bytearray(content)

        if len(content) < self.MIN_ZIP_FILE_SIZE:  # pragma: no cover
            return False

        if len(content) > self.MAX_ZIP_FILE_SIZE:  # pragma: no cover
            return False

        fp = io.BytesIO(content)
        if not zipfile.is_zipfile(fp):
            log.warning("[MIMEHANDLER (ZIP)][ERROR] Invalid ZIP file")
            return False

        try:
            zipdata = zipfile.ZipFile(fp)  # pylint: disable=consider-using-with
        except Exception as e:  # pragma: no cover,pylint:disable=broad-except
            log.warning("[MIMEHANDLER (ZIP)][ERROR] %s", str(e))
            return False

        log.ThugLogging.log_file(content, url, sampletype="ZIP")

        for filename in zipdata.namelist():
            sample = None

            try:
                data = zipdata.read(filename)
            except Exception as e:  # pragma: no cover,pylint:disable=broad-except
                log.warning("[MIMEHANDLER (ZIP)][ERROR] %s", str(e))
                continue

            if not data:  # pragma: no cover
                continue

            if filename.lower().endswith(".js"):
                window = getattr(self, "window", None)

                if window:
                    try:
                        with window.context as ctxt:
                            ctxt.eval(data)
                    except (
                        Exception
                    ) as e:  # pragma: no cover,pylint:disable=broad-except
                        log.warning("[MIMEHANDLER (ZIP)][ERROR] %s", str(e))

                sample = log.ThugLogging.log_file(data, url, sampletype="JS")

            if sample is None:  # pragma: no cover
                sample = log.ThugLogging.log_file(data, url)

            if sample is None:  # pragma: no cover
                continue

            try:
                md5 = sample["md5"]
            except Exception as e:  # pragma: no cover,pylint:disable=broad-except
                log.warning("[MIMEHANDLER (ZIP)][ERROR] %s", str(e))
                continue

            unzipped = os.path.join(log.ThugLogging.baseDir, "unzipped")
            log.ThugLogging.store_content(unzipped, md5, data)

        return True

    def handle_rar(self, url, content):
        if len(content) < self.MIN_RAR_FILE_SIZE:  # pragma: no cover
            return False

        if len(content) > self.MAX_RAR_FILE_SIZE:  # pragma: no cover
            return False

        _, rfile = tempfile.mkstemp()
        with open(rfile, "wb") as fd:
            fd.write(content)

        try:
            rardata = rarfile.RarFile(rfile)
        except Exception as e:  # pylint:disable=broad-except
            log.warning("[MIMEHANDLER (RAR)][ERROR] %s", str(e))
            os.remove(rfile)
            return False

        log.ThugLogging.log_file(content, url, sampletype="RAR")

        for filename in rardata.namelist():
            try:
                data = rardata.read(filename)
            except Exception as e:  # pragma: no cover,pylint:disable=broad-except
                log.warning("[MIMEHANDLER (RAR)][ERROR] %s", str(e))
                continue

            if not data:  # pragma: no cover
                continue

            sample = log.ThugLogging.log_file(data, url)
            if sample is None:  # pragma: no cover
                continue

            try:
                md5 = sample["md5"]
            except Exception as e:  # pragma: no cover,pylint:disable=broad-except
                log.warning("[MIMEHANDLER (RAR)][ERROR] %s", str(e))
                continue

            unzipped = os.path.join(log.ThugLogging.baseDir, "unzipped")
            log.ThugLogging.store_content(unzipped, md5, data)

        os.remove(rfile)
        return True

    @property
    def javaWebStartUserAgent(self):
        javaplugin = log.ThugVulnModules._javaplugin.split(".")
        last = javaplugin.pop()
        version = f"{'.'.join(javaplugin)}_{last}"
        return f"JNLP/6.0 javaws/{version} (b04) Java/{version}"

    def handle_java_jnlp(self, url, data):
        headers = {}
        headers["Connection"] = "keep-alive"

        try:
            soup = bs4.BeautifulSoup(data, "lxml")
        except Exception:  # pragma: no cover,pylint:disable=broad-except
            return

        jnlp = soup.find("jnlp")
        if jnlp is None:  # pragma: no cover
            return

        codebase = jnlp.attrs["codebase"] if "codebase" in jnlp.attrs else ""

        log.ThugLogging.add_behavior_warn(
            description="[JNLP Detected]", method="Dynamic Analysis"
        )

        jars = soup.find_all("jar")
        if not jars:  # pragma: no cover
            return

        headers["User-Agent"] = self.javaWebStartUserAgent

        for jar in jars:
            try:
                url = f"{codebase}{jar.attrs['href']}"
                log.DFT.window._navigator.fetch(
                    url, headers=headers, redirect_type="JNLP"
                )
            except Exception:  # pragma: no cover,pylint:disable=broad-except
                pass

    def handle_svg_xml(
        self, url, data
    ):  # pragma: no cover,pylint:disable=unused-argument
        try:
            soup = bs4.BeautifulSoup(data, "xml")
        except Exception:  # pragma: no cover,pylint:disable=broad-except
            return

        scripts = soup.find_all("script")
        if not scripts:
            return  # pragma: no cover

        window = getattr(self, "window", None)
        if not window:
            return  # pragma: no cover

        for script in scripts:
            with window.context as ctxt:
                try:
                    ctxt.eval(script.text)
                except Exception as e:  # pragma: no cover,pylint:disable=broad-except
                    log.warning("[MIMEHANDLER (SVG+XML)][ERROR] %s", str(e))

    def handle_json(self, url, data):  # pylint:disable=unused-argument
        try:
            content = json.loads(data)
        except Exception:  # pragma: no cover,pylint:disable=broad-except
            return False

        if not isinstance(content, dict):  # pragma: no cover
            return False

        headers = {}
        headers["Connection"] = "keep-alive"

        for key in content.keys():
            if key.lower() in ("@content.downloadurl",):
                try:
                    log.DFT.window._navigator.fetch(
                        content[key], headers=headers, redirect_type="JSON"
                    )
                except Exception:  # pylint:disable=broad-except
                    pass

        return True

    def passthrough(self, url, data):  # pylint:disable=unused-argument
        """
        The method passthrough is the default handler associated to
        almost all Content-Types with the few exceptions defined in
        register_empty_handlers.
        """
        return True

    def get_handler(self, key):
        if self.mimehandler_pyhooks in (MIMEHANDLER_PYHOOKS_REQUIRED,):
            self.init_pyhooks()

        return self[key.split(";")[0]]
