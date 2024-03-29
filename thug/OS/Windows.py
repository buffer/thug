#!/usr/bin/env python
#
# Windows.py
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


security_sys = (
    "afwcore.sys",
    "avgtpx86.sys",
    "avipbb.sys",
    "BkavAuto.sys",
    "catflt.sys",
    "cmderd.sys",
    "eamon.sys",
    "econceal.sys",
    "EstRtw.sys",
    "FortiRdr.sys",
    "FStopW.sys",
    "HookHelp.sys",
    "ImmunetProtect.sys",
    "kl1.sys",
    "klflt.sys",
    "klif.sys",
    "kneps.sys",
    "MpFilter.sys",
    "nvcw32mf.sys",
    "Parity.sys",
    "prl_boot.sys",
    "prl_fs.sys",
    "prl_kmdd.sys",
    "prl_memdev.sys",
    "prl_mouf.sys",
    "prl_pv32.sys",
    "prl_sound.sys",
    "prl_strg.sys",
    "prl_tg.sys",
    "prl_time.sys",
    "protreg.sys",
    "SophosBootDriver.sys",
    "SYMEVENT.SYS",
    "SysGuard.sys",
    "tmactmon.sys",
    "tmcomm.sys",
    "tmevtmgr.sys",
    "TMEBC32.sys",
    "tmeext.sys",
    "tmnciesc.sys",
    "tmtdi.sys",
    "vbengnt.sys",
    "vm3dmp.sys",
    "vmhgfs.sys",
    "vmusbmouse.sys",
    "vmmouse.sys",
    "vmhgfs.sys",
    "vmnet.sys",
    "vmusbmouse.sys",
    "vmx86.sys",
    "vmxnet.sys",
    "VBoxGuest.sys",
    "VBoxMouse.sys",
    "VBoxSF.sys",
    "VBoxVideo.sys",
    "WpsHelper.sys",
    "7z.exe",
    "a2cmd.exe",
    "acs.exe",
    "agb.exe",
    "ARKIT.EXE",
    "asOEHook.dll",
    "avcuf32.dll",
    "AYLaunch.exe",
    "AVG Secure Search_toolbar.dll",
    "avgdttbx.dll",
    "avp.exe",
    "avzkrnl.dll",
    "BdProvider.dll",
    "Bka.exe",
    "cfgconv.exe",
    "DoScan.exe",
    "drwebsp.dll",
    "egui.exe",
    "EMET.dll",
    "Fiddler.exe",
    "FortiClient.exe",
    "FPWin.exe",
    "fsesgui.exe",
    "fsgkiapi.dll",
    "FSLSP.DLL",
    "fshook32.dll",
    "klwtblc.dll",
    "instapi.dll",
    "ips.exe",
    "iTunesHelper.exe",
    "KVPopup.exe",
    "LangSel.exe",
    "McShield.dll",
    "mfc42.dll",
    "muis.dll",
    "mytilus3.dll",
    "mytilus3_worker.dll",
    "nse.exe",
    "nsphsvr.exe",
    "pctsGui.exe",
    "RavMonD.exe",
    "remote_eka_prague_loader.dll",
    "SavMain.exe",
    "setup_nativelook.exe",
    "shellex.dll",
    "shortcut.exe",
    "SOPHOS~1.DLL",
    "sqlvdi.dll",
    "SUPERAntiSpyware.exe",
    "TPAutoConnSvc.exe",
    "unGuardX.exe",
    "uninst.exe",
    "uiWinMgr.exe",
    "V3Main.exe",
    "Vrmonnt.exe",
    "winpers.exe",
    "WinRAR.exe",
    "wpsman.dll",
    "WZSHLSTB.DLL",
    "ZipSendB.dll",
)


win32_folders = (
    "c:\\windows",
    "c:\\windows\\system32",
    "c:\\windows\\system32\\drivers",
    "c:\\windows\\system32\\drivers\\etc",
)

win32_files = ("c:\\windows\\system32\\drivers\\etc\\hosts",)

win32_registry = {
    "hklm\\software\\microsoft\\windows nt\\currentversion\\systemroot": "C:\\Windows",
    "hklm\\software\\microsoft\\windows\\currentversion\\explorer\\shell folders\\common desktop": "",
}

win32_registry_map = {
    "hklm\\software\\microsoft\\windows\\currentversion\\programfilesdir": "ProgramFiles",
}
