#!/usr/bin/env python
#
# MAEC.py
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

import sys
import datetime
import MAEC_v1_1 as maec

NAMESPACEDEF_ = 'xmlns:ns1="http://xml/metadataSharing.xsd" xmlns="http://maec.mitre.org/XMLSchema/maec-core-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maec.mitre.org/XMLSchema/maec-core-1 file:MAEC_v1.1.xsd"'

class MAEC:
    def __init__(self, thug_version):
        self._tools = ({
                        'id'            : 'maec:thug:tol:1',
                        'Name'          : 'Thug',
                        'Version'       : thug_version,
                        'Vendor'        : None,
                        'Organization'  : 'The Honeynet Project',
                       }, )

        self.id              = self.make_counter(2)
        self.associated_code = None
        self.object_pool     = None
        self.signatures      = list()

        self.init_tools_used() 
        self.create_maec_bundle()
        self.add_analysis_to_analyses()
        self.add_subject_to_analysis()

    def create_maec_bundle(self):
        self.analyses    = maec.Analyses()
        self.behaviors   = maec.Behaviors()
        self.pools       = maec.Pools()
        self.maec_bundle = maec.BundleType(id             = "maec:thug:bnd:1",
                                           Analyses       = self.analyses,
                                           Behaviors      = self.behaviors,
                                           Pools          = self.pools,
                                           schema_version = 1.1)

    def init_tools_used(self):
        self.tools_used = maec.Tools_Used()
        
        for t in self._tools:
            tool = maec.ToolType(id           = t['id'],
                                 Name         = t['Name'],
                                 Version      = t['Version'],
                                 Vendor       = t['Vendor'],
                                 Organization = t['Organization'])
        
            self.tools_used.add_Tool(tool)

    def make_counter(self, p):
        id = p
        while True:
            yield id
            id += 1

    def create_object(self, url):
        object_id = "maec:thug:obj:%d" % (next(self.id))

        internet_object_attributes = maec.Internet_Object_Attributes(URI = url)

        return maec.ObjectType(type_                      = "URI",
                               object_name                = url,
                               Internet_Object_Attributes = internet_object_attributes,
                               id                         = object_id)

    def add_object_to_subject(self, url):
        self.object = self.create_object(url)
        self.subject.set_Object(self.object)

    def set_url(self, url):
        self.add_object_to_subject(url)

    def create_analysis(self):
        return maec.AnalysisType(id              = 'maec:thug:ana:%d' % (next(self.id)),
                                 start_datetime  = datetime.datetime.now(),
                                 analysis_method = "Dynamic",
                                 Tools_Used      = self.tools_used)

    def add_analysis_to_analyses(self):
        analyses      = self.maec_bundle.get_Analyses()
        self.analysis = self.create_analysis()

        analyses.add_Analysis(self.analysis)

    def finalize_analysis(self):
        self.analysis.set_complete_datetime(datetime.datetime.now())

    def add_subject_to_analysis(self):
        self.subject = maec.Subject()

        self.analysis.add_Subject(self.subject)

    def add_associated_code_to_object(self):
        if self.associated_code:
            return

        self.associated_code = maec.Associated_Code()
        self.object.set_Associated_Code(self.associated_code)

    def normalize_snippet(self, snippet):  
        _snippet = '\n'
        for line in snippet.splitlines():
            _snippet += 5 * '\t' + line + '\n'
        _snippet += 4 * '\t'

        return _snippet.encode('ascii', 'ignore')

    def add_snippet_to_associated_code(self, snippet, language, relationship, method = "Dynamic Analysis"):
        discovery_method = self.create_discovery_method(method)
        
        code = self.create_code_segment(self.normalize_snippet(snippet), 
                                        language,
                                        discovery_method)

        snippet = maec.Associated_Code_Snippet()
        snippet.set_Code_Snippet(code)
        snippet.set_Nature_Of_Relationship(relationship)
        self.associated_code.add_Associated_Code_Snippet(snippet)

    def add_code_snippet(self, snippet, language, relationship):
        self.add_associated_code_to_object()
        self.add_snippet_to_associated_code(snippet, language, relationship)

    def create_code_segment(self, snippet, language, discovery_method):
        return maec.CodeType(Code_Segment     = snippet, 
                             Discovery_Method = discovery_method,
                             language         = language,
                             xorpattern       = None,
                             id               = "maec:thug:cde:%d" % (next(self.id)))

    def create_discovery_method(self, method):
        return maec.DiscoveryMethod(method  = method,
                                    tool_id = "maec:thug:tol:%d" % (next(self.id)))

    def add_behavior(self, description = None, cve = None, method = "Dynamic Analysis"):
        if not cve and not description:
            return

        id       = "maec:thug:bhv:%s" % (next(self.id))
        behavior = maec.BehaviorType(id = id)
        behavior.set_Discovery_Method(self.create_discovery_method(method))

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
            desc.add_Text(description)
            behavior.set_Description(desc)
        
        self.behaviors.add_Behavior(behavior)

    def check_signature(self, signature):
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

    def add_object(self, signature):
        if self.check_signature(signature):
            return

        hashes    = maec.Hashes()
        file_type = None

        for item in signature:
            if item in ('type', ):
                file_type = signature[item]
                continue

            hash = maec.HashType(type_      = item, 
                                 Hash_Value = signature[item])

            hashes.add_Hash(hash)

        if not file_type:
            return

        file_type  = maec.File_Type(type_ = file_type)
        filesystem = maec.File_System_Object_Attributes(Hashes    = hashes,
                                                        File_Type = file_type)

        object = maec.ObjectType(id = "maec:thug:obj:%d" % (next(self.id)))
        object.set_File_System_Object_Attributes(filesystem)

        if not self.pools.get_Object_Pool():
            self.object_pool = maec.Object_Pool()
            self.pools.set_Object_Pool(self.object_pool)

        self.object_pool.add_Object(object)

    def export(self, outfile = sys.stdout):
        self.maec_bundle.export(outfile, 
                                0, 
                                name_         = 'MAEC_Bundle',
                                namespace_    = '',
                                namespacedef_ = NAMESPACEDEF_)

