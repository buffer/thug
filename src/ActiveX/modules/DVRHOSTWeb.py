# DVRHOST Web CMS OCX 1.x
# CVE-NOMATCH

acct = ActiveXAcct[self]

def TimeSpanFormat(arg0, arg1):
    global acct

    if len(arg1) > 512:
        acct.add_alert('DVRHOST Web CMS OCX overflow in TimeSpanFormat()')

self.TimeSpanFormat = TimeSpanFormat
