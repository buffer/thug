# HP Info Center ActiveX Control
# CVE-2007-6331, CVE-2007-6332, CVE-2007-6333

import logging

log = logging.getLogger("Thug")


def LaunchApp(self, prog, args, unk):  # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(
        f"[HP Info Center ActiveX] LaunchApp called to run: {prog} {args}",
        "CVE-2007-6331",
    )
    log.ThugLogging.log_exploit_event(
        self._window.url,
        "HP Info Center ActiveX",
        "LaunchApp called to run",
        cve="CVE-2007-6331",
        forward=False,
        data={"command": prog, "args": args},
    )

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6331")


def SetRegValue(self, key, section, keyname, value):
    log.ThugLogging.add_behavior_warn(
        f"[HP Info Center ActiveX] SetRegValue: {str(key)}/{str(section)}/{str(keyname)} "
        f"set to {str(value)}",
        "CVE-2007-6332",
    )

    log.ThugLogging.log_exploit_event(
        self._window.url,
        "HP Info Center ActiveX",
        "SetRegValue",
        cve="CVE-2007-6332",
        forward=False,
        data={
            "key": str(key),
            "section": str(section),
            "keyname": str(keyname),
            "value": str(value),
        },
    )

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6332")


def GetRegValue(self, key, section, keyname):
    log.ThugLogging.add_behavior_warn(
        f"[HP Info Center ActiveX] GetRegValue, reading: "
        f"{str(key)}/{str(section)}/{str(keyname)}",
        "CVE-2007-6333",
    )

    log.ThugLogging.log_exploit_event(
        self._window.url,
        "HP Info Center ActiveX",
        "GetRegValue",
        cve="CVE-2007-6333",
        forward=False,
        data={"key": str(key), "section": str(section), "keyname": str(keyname)},
    )

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6333")


def EvaluateRules(self):
    log.ThugLogging.log_exploit_event(
        self._window.url, "HP Info Center ActiveX", "EvaluateRules"
    )


def SaveToFile(self, path):
    log.ThugLogging.add_behavior_warn(
        f"[HP Info Center ActiveX] SaveToFile(), writes to {path}"
    )
    log.ThugLogging.log_exploit_event(
        self._window.url,
        "HP Info Center ActiveX",
        "SaveToFile",
        data={"filename": path},
        forward=False,
    )


def ProcessRegistryData(self, parm):
    log.ThugLogging.add_behavior_warn(
        f"[HP Info Center ActiveX] ProcessRegistryData: {parm} "
    )
    log.ThugLogging.log_exploit_event(
        self._window.url,
        "HP Info Center ActiveX",
        "ProcessRegistryData",
        data={"param": parm},
        forward=False,
    )
