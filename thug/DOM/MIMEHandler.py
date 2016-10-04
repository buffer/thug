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
log = logging.getLogger("Thug")

import base64
import hashlib
import zipfile
import rarfile
import tempfile

try:
    from cStringIO import StringIO
except ImportError:
    try:
        from StringIO import StringIO
    except ImportError:
        from io import StringIO

SSDEEP = True
try:
    import ssdeep
except ImportError:
    SSDEEP = False

import bs4 as BeautifulSoup

PEEPDF = True
try:
    from peepdf.PDFCore import PDFParser, vulnsDict
except:
    PEEPDF = False

from datetime import datetime
from lxml import etree

ANDROGUARD = True
try:
    from androguard.core import androconf
    from androguard.core.bytecodes import apk
    from androguard.core.bytecodes import dvm
    from androguard.core.analysis import analysis
except ImportError:
    log.warning("[WARNING] Androguard not found - APK analysis disabled")
    ANDROGUARD = False


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
                 "application/hta",
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
        self.register_pdf_handlers()
        self.register_android_handlers()
        self.register_java_jnlp_handlers()

    def register_empty_handlers(self):
        self['application/javascript']   = None
        self['application/x-javascript'] = None
        self['text/css']                 = None
        self['text/html']                = None
        #self['text/plain']              = None
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

    def register_pdf_handlers(self):
        if PEEPDF:
            self.register_handler('application/pdf', self.handle_pdf)

    def register_android_handlers(self):
        if ANDROGUARD:
            self['application/vnd.android.package-archive'] = self.handle_android

    def register_java_jnlp_handlers(self):
        self['application/x-java-jnlp-file'] = self.handle_java_jnlp

    def handle_fallback(self, url, content):
        for handler in self.handlers:
            try:
                if handler(url, content):
                    return True
            except:
                pass
        return False

    def handle_zip(self, url, content):
        fp = StringIO(content)
        if not zipfile.is_zipfile(fp):
            return False

        try:
            zipdata = zipfile.ZipFile(fp)
        except: #pylint:disable=bare-except
            return False

        for filename in zipdata.namelist():
            try:
                data = zipdata.read(filename)
            except: #pylint:disable=bare-except
                continue

            sample = log.ThugLogging.log_file(data)
            if sample is None:
                continue

            try:
                md5 = sample['md5']
            except: #pylint:disable=bare-except
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
        except: #pylint:disable=bare-except
            os.remove(rfile)
            return False

        for filename in rardata.namelist():
            try:
                data = rardata.read(filename)
            except: #pylint:disable=bare-except
                continue

            sample = log.ThugLogging.log_file(data)
            if sample is None:
                continue

            try:
                md5 = sample['md5']
            except: #pylint:disable=bare-except
                continue

            unzipped = os.path.join(log.ThugLogging.baseDir, 'unzipped')
            log.ThugLogging.store_content(unzipped, md5, data)

        os.remove(rfile)
        return True

    def getPeepXML(self, statsDict, url):
        """
            Slightly modified version of Peepdf getPeepXML function
        """

        root              = etree.Element('peepdf_analysis',
                                          url    = 'http://peepdf.eternal-todo.com',
                                          author = 'Jose Miguel Esparza')

        analysisDate      = etree.SubElement(root, 'date')
        analysisDate.text = datetime.today().strftime('%Y-%m-%d %H:%M')
        basicInfo         = etree.SubElement(root, 'basic')
        fileName          = etree.SubElement(basicInfo, 'filename')
        fileName.text     = statsDict['File']
        md5               = etree.SubElement(basicInfo, 'md5')
        md5.text          = statsDict['MD5']
        sha1              = etree.SubElement(basicInfo, 'sha1')
        sha1.text         = statsDict['SHA1']
        sha256            = etree.SubElement(basicInfo, 'sha256')
        sha256.text       = statsDict['SHA256']
        size              = etree.SubElement(basicInfo, 'size')
        size.text         = statsDict['Size']
        detection         = etree.SubElement(basicInfo, 'detection')

        if statsDict['Detection'] != [] and statsDict['Detection'] is not None:
            detectionRate        = etree.SubElement(detection, 'rate')
            detectionRate.text   = '%d/%d' % (statsDict['Detection'][0], statsDict['Detection'][1])
            detectionReport      = etree.SubElement(detection, 'report_link')
            detectionReport.text = statsDict['Detection report']

        version      = etree.SubElement(basicInfo, 'pdf_version')
        version.text = statsDict['Version']
        #binary       = etree.SubElement(basicInfo, 'binary', status = statsDict['Binary'].lower())
        #linearized   = etree.SubElement(basicInfo, 'linearized', status = statsDict['Linearized'].lower())
        encrypted    = etree.SubElement(basicInfo, 'encrypted', status = statsDict['Encrypted'].lower())

        if statsDict['Encryption Algorithms'] != []:
            algorithms = etree.SubElement(encrypted, 'algorithms')
            for algorithmInfo in statsDict['Encryption Algorithms']:
                algorithm      = etree.SubElement(algorithms, 'algorithm', bits = str(algorithmInfo[1]))
                algorithm.text = algorithmInfo[0]

        updates       = etree.SubElement(basicInfo, 'updates')
        updates.text  = statsDict['Updates']
        objects       = etree.SubElement(basicInfo, 'num_objects')
        objects.text  = statsDict['Objects']
        streams       = etree.SubElement(basicInfo, 'num_streams')
        streams.text  = statsDict['Streams']
        comments      = etree.SubElement(basicInfo, 'comments')
        comments.text = statsDict['Comments']
        errors        = etree.SubElement(basicInfo, 'errors', num = str(len(statsDict['Errors'])))

        for error in statsDict['Errors']:
            errorMessageXML      = etree.SubElement(errors, 'error_message')
            errorMessageXML.text = error

        advancedInfo = etree.SubElement(root, 'advanced')

        for version in range(len(statsDict['Versions'])):
            statsVersion = statsDict['Versions'][version]
            if version == 0:
                versionType = 'original'
            else:
                versionType = 'update'

            versionInfo = etree.SubElement(advancedInfo, 'version', num = str(version), type = versionType)
            catalog     = etree.SubElement(versionInfo, 'catalog')

            if statsVersion['Catalog']:
                catalog.set('object_id', statsVersion['Catalog'])

            info = etree.SubElement(versionInfo, 'info')
            if statsVersion['Info']:
                info.set('object_id', statsVersion['Info'])

            objects = etree.SubElement(versionInfo, 'objects', num = statsVersion['Objects'][0])

            for _id in statsVersion['Objects'][1]:
                _object = etree.SubElement(objects, 'object', id = str(_id))

                if statsVersion['Compressed Objects']:
                    if _id in statsVersion['Compressed Objects'][1]:
                        _object.set('compressed', 'true')
                    else:
                        _object.set('compressed', 'false')

                if statsVersion['Errors']:
                    if _id in statsVersion['Errors'][1]:
                        _object.set('errors', 'true')
                    else:
                        _object.set('errors', 'false')

            streams = etree.SubElement(versionInfo, 'streams', num = statsVersion['Streams'][0])

            for _id in statsVersion['Streams'][1]:
                stream = etree.SubElement(streams, 'stream', id = str(_id))

                if statsVersion['Xref Streams']:
                    if _id in statsVersion['Xref Streams'][1]:
                        stream.set('xref_stream', 'true')
                    else:
                        stream.set('xref_stream', 'false')

                if statsVersion['Object Streams']:
                    if _id in statsVersion['Object Streams'][1]:
                        stream.set('object_stream', 'true')
                    else:
                        stream.set('object_stream', 'false')

                if statsVersion['Encoded']:
                    if _id in statsVersion['Encoded'][1]:
                        stream.set('encoded', 'true')
                        if statsVersion['Decoding Errors']:
                            if _id in statsVersion['Decoding Errors'][1]:
                                stream.set('decoding_errors', 'true')
                            else:
                                stream.set('decoding_errors', 'false')
                    else:
                        stream.set('encoded', 'false')

            jsObjects = etree.SubElement(versionInfo, 'js_objects')

            if statsVersion['Objects with JS code']:
                for _id in statsVersion['Objects with JS code'][1]:
                    etree.SubElement(jsObjects, 'container_object', id = str(_id))

            actions    = statsVersion['Actions']
            events     = statsVersion['Events']
            vulns      = statsVersion['Vulns']
            elements   = statsVersion['Elements']
            suspicious = etree.SubElement(versionInfo, 'suspicious_elements')

            if events or actions or vulns or elements:
                if events:
                    triggers = etree.SubElement(suspicious, 'triggers')
                    for event in events:
                        trigger = etree.SubElement(triggers, 'trigger', name = event)
                        for _id in events[event]:
                            log.ThugLogging.log_exploit_event(url,
                                                              "Adobe Acrobat Reader",
                                                              "Adobe Acrobat Reader suspicious trigger: %s [object %s]" % (event, _id, )
                                                              )
                            etree.SubElement(trigger, 'container_object', id = str(_id))
                if actions:
                    actionsList = etree.SubElement(suspicious, 'actions')
                    for action in actions:
                        actionInfo = etree.SubElement(actionsList, 'action', name = action)
                        for _id in actions[action]:
                            log.ThugLogging.log_exploit_event(url,
                                                              "Adobe Acrobat Reader",
                                                              "Adobe Acrobat Reader suspicious action: %s [object %s]" % (action, _id, )
                                                              )
                            etree.SubElement(actionInfo, 'container_object', id = str(_id))

                if elements:
                    elementsList = etree.SubElement(suspicious, 'elements')
                    for element in elements:
                        elementInfo = etree.SubElement(elementsList, 'element', name = element)
                        if element in vulnsDict:
                            for vulnCVE in vulnsDict[element]:
                                if isinstance(vulnCVE, (list, tuple)):
                                    vulnCVE=",".join(vulnCVE)

                                log.ThugLogging.log_exploit_event(url,
                                                                  "Adobe Acrobat Reader",
                                                                  "Adobe Acrobat Reader Exploit (%s)" % (vulnCVE, ),
                                                                  cve = vulnCVE)
                                cve = etree.SubElement(elementInfo, 'cve')
                                cve.text = vulnCVE
                        for _id in elements[element]:
                            etree.SubElement(elementInfo, 'container_object', id = str(_id))
                if vulns:
                    vulnsList = etree.SubElement(suspicious, 'js_vulns')
                    for vuln in vulns:
                        vulnInfo = etree.SubElement(vulnsList, 'vulnerable_function', name = vuln)
                        if vuln in vulnsDict:
                            for vulnCVE in vulnsDict[vuln]:
                                if isinstance(vulnCVE, (list, tuple)):
                                    vulnCVE=",".join(vulnCVE)

                                log.ThugLogging.log_exploit_event(url,
                                                                  "Adobe Acrobat Reader",
                                                                  "Adobe Acrobat Reader Exploit (%s)" % (vulnCVE, ),
                                                                  cve = vulnCVE)
                                cve = etree.SubElement(vulnInfo, 'cve')
                                cve.text = vulnCVE
                        for _id in vulns[vuln]:
                            etree.SubElement(vulnInfo, 'container_object', id = str(_id))

            urls           = statsVersion['URLs']
            #suspiciousURLs = etree.SubElement(versionInfo, 'suspicious_urls')

            if urls:
                for url in urls:
                    urlInfo      = etree.SubElement(versionInfo, 'url')
                    urlInfo.text = url

        return etree.tostring(root, pretty_print = True)

    def swf_mastah(self, pdf, statsDict, url):
        """
            This code is taken from SWF Mastah by Brandon Dixon
        """
        swfdir = os.path.join(log.ThugLogging.baseDir, 'dropped', 'swf')
        count  = 0

        for version in range(len(statsDict['Versions'])): #pylint:disable=unused-variable
            body = pdf.body[count]
            objs = body.objects

            for index in objs:
                #oid    = objs[index].id
                #offset = objs[index].offset
                #size   = objs[index].size
                details = objs[index].object

                if details.type in ("stream", ):
                    #encoded_stream = details.encodedStream
                    decoded_stream = details.decodedStream
                    header         = decoded_stream[:3]
                    is_flash       = [s for s in objs if header in ("CWS", "FWS")]

                    if is_flash:
                        data   = decoded_stream.strip()
                        sample = log.ThugLogging.log_file(data, url)
                        if sample is None:
                            continue

                        swffile = "%s.swf" % (sample["md5"], )
                        log.ThugLogging.store_content(swfdir, swffile, data)
                        log.warning("[PDF] Embedded SWF %s extracted from PDF %s", sample["md5"], statsDict["MD5"])

            count += 1

    def handle_pdf(self, url, content):
        sample = log.ThugLogging.build_sample(content, url)
        if sample is None or sample['type'] not in ('PDF', ):
            return

        fd, rfile = tempfile.mkstemp()
        with open(rfile, 'wb') as fd:
            fd.write(content)

        pdfparser = PDFParser()

        try:
            ret, pdf = pdfparser.parse(rfile, forceMode = True, looseMode = True) #pylint:disable=unused-variable
        except: #pylint:disable=bare-except
            os.remove(rfile)
            return False

        statsDict = pdf.getStats()
        analysis  = self.getPeepXML(statsDict, url)

        log_dir = os.path.join(log.ThugLogging.baseDir, "analysis", "pdf")
        log.ThugLogging.log_peepdf(log_dir, sample, analysis)

        self.swf_mastah(pdf, statsDict, url)
        os.remove(rfile)
        return True

    def do_build_apk_report(self, a):
        output = StringIO()

        a.get_files_types()

        output.write("[FILES] \n")
        for i in a.get_files():
            try:
                output.write("\t%s %s %x\n" % (i, a.files[i], a.files_crc32[i], ))
            except KeyError:
                output.write("\t%s %x\n" % (i, a.files_crc32[i], ))

        output.write("\n[PERMISSIONS] \n")
        details_permissions = a.get_details_permissions()
        for i in details_permissions:
            output.write("\t%s %s\n" % (i, details_permissions[i], ))

        output.write("\n[MAIN ACTIVITY]\n\t%s\n" % (a.get_main_activity(), ))

        output.write("\n[ACTIVITIES] \n")
        activities = a.get_activities()
        for i in activities:
            filters = a.get_intent_filters("activity", i)
            output.write("\t%s %s\n" % (i, filters or "", ))

        output.write("\n[SERVICES] \n")
        services = a.get_services()
        for i in services:
            filters = a.get_intent_filters("service", i)
            output.write("\t%s %s\n" % (i, filters or "", ))

        output.write("\n[RECEIVERS] \n")
        receivers = a.get_receivers()
        for i in receivers:
            filters = a.get_intent_filters("receiver", i)
            output.write("\t%s %s\n" % (i, filters or "", ))

        output.write("\n[PROVIDERS]\n\t%s\n\n" % (a.get_providers(), ))

        vm  = dvm.DalvikVMFormat(a.get_dex())
        vmx = analysis.uVMAnalysis(vm)

        output.write("Native code      : %s\n"   % (analysis.is_native_code(vmx), ))
        output.write("Dynamic code     : %s\n"   % (analysis.is_dyn_code(vmx), ))
        output.write("Reflection code  : %s\n"   % (analysis.is_reflection_code(vmx), ))
        output.write("ASCII Obfuscation: %s\n\n" % (analysis.is_ascii_obfuscation(vm), ))

        for i in vmx.get_methods():
            i.create_tags()
            if not i.tags.empty():
                output.write("%s %s %s\n" % (i.method.get_class_name(),
                                             i.method.get_name(),
                                             i.tags, ))

        return output

    def save_apk_report(self, sample, a, url):
        output  = self.do_build_apk_report(a)
        log_dir = os.path.join(log.ThugLogging.baseDir, "analysis", "apk")
        log.ThugLogging.log_androguard(log_dir, sample, output.getvalue())

    def build_apk_sample(self, data, url = None):
        sample = {
            "md5"   : hashlib.md5(data).hexdigest(),
            "sha1"  : hashlib.sha1(data).hexdigest(),
            "raw"   : data,
            "data"  : base64.b64encode(data),
            "type"  : "APK",
        }

        if SSDEEP:
            sample['ssdeep'] = ssdeep.hash(data)

        return sample

    def handle_android(self, url, content):
        ret = False

        fd, rfile = tempfile.mkstemp()
        with open(rfile, 'wb') as fd:
            fd.write(content)

        ret_type = androconf.is_android(rfile)

        if ret_type not in ("APK", ):
            os.remove(rfile)
            return ret

        try :
            a = apk.APK(rfile, zipmodule = 2)
            if a.is_valid_APK():
                sample = self.build_apk_sample(content, url)
                self.save_apk_report(sample, a, url)
                ret = True
        except: #pylint:disable=bare-except
            pass

        os.remove(rfile)
        return ret

    @property
    def javaWebStartUserAgent(self):
        javaplugin = log.ThugVulnModules._javaplugin.split('.')
        last = javaplugin.pop()
        version =  '%s_%s' % ('.'.join(javaplugin), last)
        return "JNLP/6.0 javaws/%s (b04) Java/%s" % (version, version, )

    def handle_java_jnlp(self, url, data):
        headers = dict()
        headers['Connection'] = 'keep-alive'

        try:
            soup = BeautifulSoup.BeautifulSoup(data, "lxml")
        except: #pylint:disable=bare-except
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
            except: #pylint:disable=bare-except
                pass

    def passthrough(self, url, data):
        """
        The method passthrough is the default handler associated to
        almost all Content-Types with the few exceptions defined in
        register_empty_handlers.
        """
        return True

    def get_handler(self, key):
        return self[key]
