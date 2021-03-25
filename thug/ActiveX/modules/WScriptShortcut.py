import logging

log = logging.getLogger("Thug")


def save(self):
    log.ThugLogging.add_behavior_warn(
        "[WScript.Shortcut ActiveX] Saving link object '{}' with target '{}'".format(self.FullName, self.TargetPath))
