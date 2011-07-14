# Gateway Weblaunch ActiveX Control
# CVE-NOMATCH

acct = ActiveXAcct[self]

def DoWebLaunch(arg0, arg1, arg2, arg3):
    global acct

    if len(arg1) > 512 or len(arg3) > 512:
        acct.add_alert('GatewayWeblaunch overflow')
    else:
        acct.add_alert('GatewayWeblaunch will try to execute '+ arg1 + ' ' + arg2 + ' ' + arg3)

self.DoWebLaunch = DoWebLaunch
