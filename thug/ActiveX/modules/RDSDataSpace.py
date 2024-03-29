# Microsoft MDAC RDS.Dataspace ActiveX
# CVE-2006-0003

import logging

log = logging.getLogger("Thug")


def CreateObject(self, _object, param=""):  # pylint:disable=unused-argument
    from thug import ActiveX

    log.ThugLogging.add_behavior_warn(
        f"[Microsoft MDAC RDS.Dataspace ActiveX] CreateObject ({_object})"
    )
    log.ThugLogging.log_exploit_event(
        self._window.url,
        "Microsoft MDAC RDS.Dataspace ActiveX",
        "CreateObject",
        cve="CVE-2006-0003",
        forward=False,
        data={"object": _object},
    )

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2006-0003")
    return ActiveX.ActiveX._ActiveXObject(self._window, _object)
