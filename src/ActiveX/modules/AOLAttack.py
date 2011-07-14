
acct = ActiveXAcct[self]

def LinkSBIcons():
    global acct

    acct.add_alert('AOLActiveX attack in LinkSBIcons function')

self.LinkSBIcons = LinkSBIcons
