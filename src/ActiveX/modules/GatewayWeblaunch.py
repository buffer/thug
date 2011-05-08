# Gateway Weblaunch ActiveX Control
# CVE-NOMATCH

def DoWebLaunch(arg0,arg1,arg2,arg3):
	if len(arg1)>512 or len(arg3)>512:
		add_alert('GatewayWeblaunch overflow')
	else:
		add_alert('GatewayWeblaunch will try to execute '+ arg1 +' '+ arg2 + ' ' +arg3)

self.DoWebLaunch=DoWebLaunch
