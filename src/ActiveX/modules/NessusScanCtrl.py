# Nessus Vunlnerability Scanner ScanCtrl ActiveX COntrol
# CVE-2007-4061, CVE-2007-4062, CVE-2007-4031

def deleteReport(arg):
	if arg.find('SYSTEM32') != -1:
		add_alert('Nessus ScanCtrl SYSTEM32 activity')
	if arg.find('Autostart') != -1:
		add_alert('Nessus ScanCtrl Autostart activity')
	if arg.find('../') != -1:
		add_alert('Nessus ScanCtrl ../ activity')

def deleteNessusRC(arg):
	if arg.find('SYSTEM32') != -1:
		add_alert('Nessus ScanCtrl SYSTEM32 activity')
	if arg.find('Autostart') != -1:
		add_alert('Nessus ScanCtrl Autostart activity')
	if arg.find('../') != -1:
		add_alert('Nessus ScanCtrl ../ activity')

def saveNessusRC(arg):
	if arg.find('SYSTEM32') != -1:
		add_alert('Nessus ScanCtrl SYSTEM32 activity')
	if arg.find('Autostart') != -1:
		add_alert('Nessus ScanCtrl Autostart activity')
	if arg.find('../') != -1:
		add_alert('Nessus ScanCtrl ../ activity')

def addsetConfig(arg, arg1, arg2):
	if arg.find('SYSTEM32') != -1:
		add_alert('Nessus ScanCtrl SYSTEM32 activity')
	if arg.find('Autostart') != -1:
		add_alert('Nessus ScanCtrl Autostart activity')
	if arg.find('../') != -1:
		add_alert('Nessus ScanCtrl ../ activity')


self.deleteReport   = deleteReport
self.deleteNessusRC = deleteNessusRC
self.saveNessusRC   = saveNessusRC
self.addsetConfig   = addsetConfig
