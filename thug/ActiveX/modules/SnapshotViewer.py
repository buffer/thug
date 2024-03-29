# Microsoft Access Snapshot Viewer
# CVE-2008-2463

import logging

log = logging.getLogger("Thug")


def PrintSnapshot(self, SnapshotPath="", CompressedPath=""):
    if SnapshotPath:
        self.SnapshotPath = SnapshotPath

    if CompressedPath:
        self.CompressedPath = CompressedPath

    msg = f"[Microsoft Access Snapshot Viewer ActiveX] SnapshotPath : {self.SnapshotPath}, CompressedPath: {self.CompressedPath}"

    log.ThugLogging.add_behavior_warn(msg, "CVE-2008-2463")
    log.ThugLogging.log_exploit_event(
        self._window.url,
        "Microsoft Access Snapshot Viewer ActiveX",
        "Print Snapshot",
        forward=False,
        cve="CVE-2008-2463",
        data={"SnapshotPath": self.SnapshotPath, "CompressedPath": self.CompressedPath},
    )
    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2008-2463")
    url = self.SnapshotPath

    try:
        self._window._navigator.fetch(url, redirect_type="CVE-2008-2463")
    except Exception:  # pragma: no cover,pylint:disable=broad-except
        log.ThugLogging.add_behavior_warn(
            "[Microsoft Access Snapshot Viewer ActiveX] Fetch failed"
        )
