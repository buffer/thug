
import logging

log = logging.getLogger("Thug")


def GetVersions(self): # pylint:disable=unused-argument
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
        versions += f"{feature}={log.ThugVulnModules.acropdf_pdf},"

    return versions


def GetVariable(self, variable): # pylint:disable=unused-argument
    if variable in ('$version', ):
        return log.ThugVulnModules.acropdf_pdf

    return "" # pragma: no cover
