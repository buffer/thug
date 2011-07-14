# CA BrightStor
# CVE-NOMATCH

acct = ActiveXAcct[self]

def AddColumn(arg0, arg1):
    global acct

    if len(arg0) > 100:
        acct.add_alert('CA BrightStor overflow in AddColumn()')

self.AddColumn = AddColumn
