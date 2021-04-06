
import logging

log = logging.getLogger("Thug")


def GetVersions(self):
    versions = ""
    for feature in ('Accessibility',
                    'AcroForm',
                    'Annots',
                    'Checkers',
                    'DigSig',
                    'DVA',
                    'eBook',
                    'EScript',
                    'HLS',
                    'IA32',
                    'MakeAccessible',
                    'Multimedia',
                    'PDDom',
                    'PPKLite',
                    'ReadOutLoud',
                    'reflow',
                    'SaveAsRTF',
                    'Search',
                    'Search5',
                    'SendMail',
                    'Spelling',
                    'Updater',
                    'weblink'):
        versions += "%s=%s," % (feature, log.ThugVulnModules.acropdf_pdf, )

    return versions


def GetVariable(self, variable):
    if variable in ('$version', ):
        return log.ThugVulnModules.acropdf_pdf

    return "" # pragma: no cover
