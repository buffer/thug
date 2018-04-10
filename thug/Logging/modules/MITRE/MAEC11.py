#!/usr/bin/env python
#
# MAEC11.py
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
import datetime

from six import StringIO

from . import MAEC_v1_1 as maec

NAMESPACEDEF_ = 'xmlns:ns1="http://xml/metadataSharing.xsd" xmlns="http://maec.mitre.org/XMLSchema/maec-core-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maec.mitre.org/XMLSchema/maec-core-1 file:MAEC_v1.1.xsd"'

log = logging.getLogger("Thug")


class MAEC11(object):
    def __init__(self, thug_version):
        self._tools = ({
                        'id'            : 'maec:thug:tol:1',
                        'Name'          : 'Thug',
                        'Version'       : thug_version,
                        'Vendor'        : None,
                        'Organization'  : 'The Honeynet Project',
                       }, )

        self.id              = self.__make_counter(2)
        self.associated_code = None
        self.object_pool     = None
        self.signatures      = list()
        self.cached_data     = None

        self.__init_tools_used()
        self.__create_maec_bundle()
        self.__add_analysis_to_analyses()
        self.__add_subject_to_analysis()

    def __make_counter(self, p):
        _id = p
        while True:
            yield _id
            _id += 1

    def __init_tools_used(self):
        self.tools_used = maec.Tools_Used()

        for t in self._tools:
            tool = maec.ToolType(id           = t['id'],
                                 Name         = t['Name'],
                                 Version      = t['Version'],
                                 Vendor       = t['Vendor'],
                                 Organization = t['Organization'])

            self.tools_used.add_Tool(tool)

    def __create_maec_bundle(self):
        self.analyses    = maec.Analyses()
        self.behaviors   = maec.Behaviors()
        self.pools       = maec.Pools()
        self.maec_bundle = maec.BundleType(id             = "maec:thug:bnd:1",
                                           Analyses       = self.analyses,
                                           Behaviors      = self.behaviors,
                                           Pools          = self.pools,
                                           schema_version = 1.1)

    def __create_analysis(self):
        return maec.AnalysisType(id              = 'maec:thug:ana:%d' % (next(self.id)),
                                 start_datetime  = datetime.datetime.now(),
                                 analysis_method = "Dynamic",
                                 Tools_Used      = self.tools_used)

    def __add_analysis_to_analyses(self):
        analyses      = self.maec_bundle.get_Analyses()
        self.analysis = self.__create_analysis()

        analyses.add_Analysis(self.analysis)

    def __add_subject_to_analysis(self):
        self.subject = maec.Subject()

    @property
    def maec11_enabled(self):
        return log.ThugOpts.maec11_logging or 'maec11' in log.ThugLogging.formats

    def finalize_analysis(self):
        self.analysis.set_complete_datetime(datetime.datetime.now())

    def create_object(self, url):
        object_id = "maec:thug:obj:%d" % (next(self.id))

        internet_object_attributes = maec.Internet_Object_Attributes(URI = url)

        return maec.ObjectType(type_                      = "URI",
                               object_name                = url,
                               Internet_Object_Attributes = internet_object_attributes,
                               id                         = object_id)

    def _add_object_to_subject(self, url):
        self.object = self.create_object(url)
        self.subject.set_Object(self.object)

    def set_url(self, url):
        if not self.maec11_enabled:
            return

        self._add_object_to_subject(url.decode('utf-8'))

    def _add_associated_code_to_object(self):
        if self.associated_code:
            return

        self.associated_code = maec.Associated_Code()
        self.object.set_Associated_Code(self.associated_code)

    def _normalize_snippet(self, snippet):
        _snippet = '\n'
        for line in snippet.splitlines():
            _snippet += 5 * '\t' + line + '\n'
        _snippet += 4 * '\t'

        try:
            return _snippet.encode('ascii', 'ignore')
        except: #pylint:disable=bare-except
            return _snippet.decode('ascii', 'ignore')

    def _add_snippet_to_associated_code(self, snippet, language, relationship, method = "Dynamic Analysis"):
        discovery_method = self._create_discovery_method(method)

        code = self._create_code_segment(self._normalize_snippet(snippet),
                                        language,
                                        discovery_method)

        snippet = maec.Associated_Code_Snippet()
        snippet.set_Code_Snippet(code)
        snippet.set_Nature_Of_Relationship(relationship)
        self.associated_code.add_Associated_Code_Snippet(snippet)

    def add_code_snippet(self, snippet, language, relationship, tag, method = "Dynamic Analysis"):
        if not self.maec11_enabled:
            return

        self._add_associated_code_to_object()
        self._add_snippet_to_associated_code(snippet, language, relationship, method)

    def _create_code_segment(self, snippet, language, discovery_method):
        return maec.CodeType(Code_Segment     = snippet,
                             Discovery_Method = discovery_method,
                             language         = language,
                             xorpattern       = None,
                             id               = "maec:thug:cde:%d" % (next(self.id)))

    def _create_discovery_method(self, method, tool = "Thug"):
        _tool_id = None

        for p in self._tools:
            if p["Name"] == tool:
                _tool_id = p["id"]
                break

        return maec.DiscoveryMethod(method  = method,
                                    tool_id = _tool_id if _tool_id else "maec:thug:tol:%d" % (next(self.id)))

    def add_behavior(self, description = None, cve = None, snippet = None, method = "Dynamic Analysis"):
        if not self.maec11_enabled:
            return

        if not cve and not description:
            return

        _id      = "maec:thug:bhv:%s" % (next(self.id))
        behavior = maec.BehaviorType(id = _id)
        behavior.set_Discovery_Method(self._create_discovery_method(method))

        purpose = maec.Purpose()

        if cve:
            t = maec.Attempted_Vulnerability_Exploit()
            t.set_vulnerability_type('Known')

            if cve:
                c = maec.CVEVulnerabilityType(cve_id = cve)
                t.set_Known_Exploit(c)

            purpose.set_Attempted_Vulnerability_Exploit(t)
            behavior.set_Purpose(purpose)

        if description:
            desc = maec.StructuredTextType()

            try:
                desc.add_Text(description)
            except: #pylint:disable=bare-except
                desc.add_Text(description.decode('utf-8'))

            behavior.set_Description(desc)

        self.behaviors.add_Behavior(behavior)

    def add_behavior_warn(self, description = None, cve = None, snippet = None, method = "Dynamic Analysis"):
        if not self.maec11_enabled:
            return

        self.add_behavior(description, cve, snippet, method)

    def _check_signature(self, signature):
        if not signature:
            return True

        if not self.pools.get_Object_Pool() or not self.signatures:
            self.signatures.append(signature)
            return False

        for p in [s for s in self.signatures if s['type'] == signature['type']]:
            if p['md5'] == signature['md5'] and p['sha1'] == signature['sha1']:
                return True

        self.signatures.append(signature)
        return False

    def _add_object(self, signature):
        if self._check_signature(signature):
            return

        hashes    = maec.Hashes()
        file_type = None

        for item in signature:
            if item in ('url', 'data', ):
                continue

            if item in ('type', ):
                file_type = signature[item]
                continue

            _hash = maec.HashType(type_     = item,
                                 Hash_Value = signature[item])

            hashes.add_Hash(_hash)

        if not file_type:
            return

        _file_type = maec.File_Type(type_ = file_type)
        filesystem = maec.File_System_Object_Attributes(Hashes    = hashes,
                                                        File_Type = _file_type)

        _object = maec.ObjectType(id = "maec:thug:obj:%d" % (next(self.id)))
        _object.set_File_System_Object_Attributes(filesystem)

        if self.object_pool is None:
            self.object_pool = maec.Object_Pool()
            self.pools.set_Object_Pool(self.object_pool)

        self.object_pool.add_Object(_object)

    def log_file(self, data, url = None, params = None):
        if not self.maec11_enabled:
            return

        self._add_object(data)

    def export(self, basedir):
        if not self.maec11_enabled:
            return

        output = StringIO()
        self.maec_bundle.export(output,
                                0,
                                name_         = 'MAEC_Bundle',
                                namespace_    = '',
                                namespacedef_ = NAMESPACEDEF_)

        if log.ThugOpts.maec11_logging and log.ThugOpts.file_logging:
            logdir = os.path.join(basedir, "analysis", "maec11")
            log.ThugLogging.store_content(logdir, 'analysis.xml', output.getvalue())

        self.cached_data = output

    def get_maec11_data(self, basedir):
        if self.cached_data:
            return self.cached_data.getvalue()

        return None
