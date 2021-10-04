import logging

log = logging.getLogger("Thug")


def isVersionSupported(self, version):
    log.ThugLogging.add_behavior_warn(f"[SilverLight] isVersionSupported('{version}')")
    return log.ThugVulnModules.silverlight.startswith(version)
