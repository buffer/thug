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

import hashlib
import zipfile
import rarfile
from peepdf.PDFCore import PDFParser, vulnsDict
from datetime import datetime
from lxml import etree

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO


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

        log.warning("[MIMEHandler] Unknown MIME Type: %s" % (key, ))
        return self.passthrough

    def __init__(self):
        for mimetype in self.mimetypes:
            self[mimetype] = self.passthrough

        self.register_empty_handlers()
        self.register_zip_handlers()
        self.register_rar_handlers()
        self.register_pdf_handlers()

    def register_empty_handlers(self):
        self['application/javascript']   = None
        self['application/x-javascript'] = None
        self['text/css']                 = None
        self['text/html']                = None
        self['text/plain']               = None
        self['text/javascript']          = None

    def register_zip_handlers(self):
        self['application/zip'] = self.handle_zip

    def register_rar_handlers(self):
        self['application/x-rar-compressed'] = self.handle_rar

    def register_pdf_handlers(self):
        self['application/pdf'] = self.handle_pdf

    def handle_zip(self, url, content):
        fp = StringIO(content)
        if not zipfile.is_zipfile(fp):
            return False

        zipdata = zipfile.ZipFile(fp)
        for filename in zipdata.namelist():
            try:
                data = zipdata.read(filename)
            except:
                continue

            sample = log.ThugLogging.log_file(data)
            if sample is None:
                continue

            try:
                md5 = sample['md5']
            except:
                continue
            

            unzipped = os.path.join(log.ThugLogging.baseDir, 'unzipped')
            try:
                os.makedirs(unzipped)
            except:
                pass

            sample_name = os.path.join(unzipped, md5, )
            with open(sample_name, 'wb') as fd:
                fd.write(data)

        return True

    def handle_rar(self, url, content):
        unzipped = os.path.join(log.ThugLogging.baseDir, 'unzipped')
        try:
            os.makedirs(unzipped)
        except:
            pass

        m = hashlib.md5()
        m.update(content)
        md5sum = m.hexdigest()
        rfile = os.path.join(unzipped, "%s.rar" % (md5sum, ))
        with open(rfile, 'wb') as fd:
            fd.write(content)

        rardata = rarfile.RarFile(rfile)
        for filename in rardata.namelist():
            try:
                data = rardata.read(filename)
            except:
                continue

            sample = log.ThugLogging.log_file(data)
            if sample is None:
                continue

            try:
                md5 = sample['md5']
            except:
                continue

            sample_name = os.path.join(unzipped, md5, )
            with open(sample_name, 'wb') as fd:
                fd.write(data)

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

        if statsDict['Detection'] != [] and statsDict['Detection'] != None:
            detectionRate        = etree.SubElement(detection, 'rate')
            detectionRate.text   = '%d/%d' % (statsDict['Detection'][0], statsDict['Detection'][1])
            detectionReport      = etree.SubElement(detection, 'report_link')
            detectionReport.text = statsDict['Detection report']

        version      = etree.SubElement(basicInfo, 'pdf_version')
        version.text = statsDict['Version']
        binary       = etree.SubElement(basicInfo, 'binary', status = statsDict['Binary'].lower())
        linearized   = etree.SubElement(basicInfo, 'linearized', status = statsDict['Linearized'].lower())
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

            for id in statsVersion['Objects'][1]:
                object = etree.SubElement(objects, 'object', id = str(id))
                
                if statsVersion['Compressed Objects']:
                    if id in statsVersion['Compressed Objects'][1]:
                        object.set('compressed', 'true')
                    else:
                        object.set('compressed', 'false')
                
                if statsVersion['Errors']:
                    if id in statsVersion['Errors'][1]:
                        object.set('errors', 'true')
                    else:
                        object.set('errors', 'false')
            
            streams = etree.SubElement(versionInfo, 'streams', num = statsVersion['Streams'][0])
            
            for id in statsVersion['Streams'][1]:
                stream = etree.SubElement(streams, 'stream', id = str(id))
                
                if statsVersion['Xref Streams']:
                    if id in statsVersion['Xref Streams'][1]:
                        stream.set('xref_stream', 'true')
                    else:
                        stream.set('xref_stream', 'false')
                
                if statsVersion['Object Streams']:
                    if id in statsVersion['Object Streams'][1]:
                        stream.set('object_stream', 'true')
                    else:
                        stream.set('object_stream', 'false')
                
                if statsVersion['Encoded']:
                    if id in statsVersion['Encoded'][1]:
                        stream.set('encoded', 'true')
                        if statsVersion['Decoding Errors']:
                            if id in statsVersion['Decoding Errors'][1]:
                                stream.set('decoding_errors', 'true')
                            else:
                                stream.set('decoding_errors', 'false')
                    else:
                        stream.set('encoded', 'false')

            jsObjects = etree.SubElement(versionInfo, 'js_objects')

            if statsVersion['Objects with JS code']:
                for id in statsVersion['Objects with JS code'][1]:
                    etree.SubElement(jsObjects, 'container_object', id = str(id))

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
                        for id in events[event]:
                            etree.SubElement(trigger, 'container_object', id = str(id))
                if actions:
                    print actions
                    actionsList = etree.SubElement(suspicious, 'actions')
                    for action in actions:
                        actionInfo = etree.SubElement(actionsList, 'action', name = action)
                        for id in actions[action]:
                            etree.SubElement(actionInfo, 'container_object', id = str(id))
                if elements:
                    elementsList = etree.SubElement(suspicious, 'elements')
                    for element in elements:
                        elementInfo = etree.SubElement(elementsList, 'element', name = element)
                        if vulnsDict.has_key(element):
                            for vulnCVE in vulnsDict[element]:
                                cve = etree.SubElement(elementInfo, 'cve')
                                cve.text = vulnCVE
                        for id in elements[element]:
                            etree.SubElement(elementInfo, 'container_object', id = str(id))
                if vulns:
                    vulnsList = etree.SubElement(suspicious, 'js_vulns')
                    for vuln in vulns:
                        vulnInfo = etree.SubElement(vulnsList, 'vulnerable_function', name = vuln)
                        if vulnsDict.has_key(vuln):
                            for vulnCVE in vulnsDict[vuln]:
                                log.ThugLogging.log_exploit_event(url, 
                                                                  "Adobe Acrobat Reader",
                                                                  "Adobe Acrobat Reader Exploit (%s)" % (vulnCVE, ), 
                                                                  cve = vulnCVE)
                                cve = etree.SubElement(vulnInfo, 'cve')
                                cve.text = vulnCVE
                        for id in vulns[vuln]:
                            etree.SubElement(vulnInfo, 'container_object', id = str(id))
            
            urls           = statsVersion['URLs']
            suspiciousURLs = etree.SubElement(versionInfo, 'suspicious_urls')
            
            if urls:
                for url in urls:
                    urlInfo      = etree.SubElement(versionInfo, 'url')
                    urlInfo.text = url

        return etree.tostring(root, pretty_print = True)

    def handle_pdf(self, url, content):
        m = hashlib.md5()
        m.update(content)
        md5sum = m.hexdigest()

        rfile = os.path.join(log.ThugLogging.baseDir, md5sum)
        with open(rfile, 'wb') as fd: 
            fd.write(content)

        pdfparser = PDFParser()
        ret, pdf  = pdfparser.parse(rfile, forceMode = True, looseMode = True)
        statsDict = pdf.getStats() 
        analysis  = self.getPeepXML(statsDict, url)

        pdflogdir = os.path.join(log.ThugLogging.baseDir, "analysis", "pdf")
        try:
            os.makedirs(pdflogdir)
        except:
            pass

        report = os.path.join(pdflogdir, "%s.xml" % (statsDict["MD5"], ))
        with open(report, 'wb') as fd:
            fd.write(analysis)

        os.remove(rfile)
        return True

    def passthrough(self, data):
        """
        The method passthrough is the default handler associated to
        almost all Content-Types with the few exceptions defined in
        register_empty_handlers. 
        """
        return True

    def get_handler(self, key):
        return self[key]
