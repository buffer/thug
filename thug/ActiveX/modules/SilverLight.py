import logging

log = logging.getLogger("Thug")


def isVersionSupported(self, version):
    log.ThugLogging.add_behavior_warn("[SilverLight] isVersionSupported('%s')" % (version, ))
    return log.ThugVulnModules.silverlight.startswith(version)
