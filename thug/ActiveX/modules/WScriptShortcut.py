import logging

log = logging.getLogger("Thug")


def save(self):
    log.ThugLogging.add_behavior_warn(
        f"[WScript.Shortcut ActiveX] Saving link object '{self.FullName}' with target '{self.TargetPath}'")
