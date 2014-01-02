// Styx Exploit Kit (rule #1)
rule Styx_1 : Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-zA-Z0-9]{150,}/ nocase
  condition:
    $url
}


// Styx Exploit Kit (rule #2)
rule Styx_2 : PluginDetect Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-zA-Z0-9]{40,}\/pdfx\.html/ nocase
  condition:
    $url
}


// Styx Exploit Kit (rule #3)
rule Styx_3 : JAR Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-zA-Z0-9]{40,}\/[a-zA-Z0-9]{4,10}\.jar/ nocase
  condition:
    $url
}


// Styx Exploit Kit (rule #4)
rule Styx_4 : PDF Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-zA-Z0-9]{40,}\/[a-zA-Z0-9]{4,10}\.pdf/ nocase
  condition:
    $url
}


// Styx Exploit Kit (rule #5)
rule Styx_5 : EOT Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-zA-Z0-9]{40,}\/[a-zA-Z0-9]{4,10}\.eot/ nocase
  condition:
    $url
}


// Styx Exploit Kit (rule #6)
rule Styx_6 : EXE Exploit_Kit
{
  meta:
    author = "Angelo Dell'Aera"
  strings:
    $url = /\/[a-zA-Z0-9]{40,}\/[a-zA-Z0-9]{4,10}\.exe/ nocase
  condition:
    $url
}


// Styx Exploit Kit (rule #7)
rule Styx_7 : EXE Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-zA-Z0-9]{150,}\/[a-zA-Z0-9]+\.exe\?[a-zA-Z0-9=]+&h=[0-9]+$/ nocase
  condition: 
    $url
}  


// Styx Exploit Kit (rule #8)
rule Styx_8 : EXE Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $a = /\/[a-zA-Z0-9]{180,}\/\w+\.exe\?o\=\d+\&h\=\d+/ nocase
    $b = /\/[a-zA-Z0-9]{180,}\/getmyfile\.exe\?o\=\d/ nocase
  condition:
    $a or $b
}

// Styx (Kein Edition) Exploit Kit (rule #1)
rule Styx_Kein_Edition_1 : EXE Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /\/\?[A-Za-z0-9]{2,10}\=[a-z0-9%]{70,}\&t\=\d+/ nocase
  condition:
    $url
}


// Styx (Kein Edition) Exploit Kit (rule #2)
rule Styx_Kein_Edition_2 : Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /(epac\.to|freetcp\.com|faqserv\.com|qpoe\.com|2waky\.com|1dumb\.com|ddns\.info|lflinkup\.com)\/((info\.php\?n=)?[0-9]{1,3}|n\/[0-9]{1,3})$/ nocase
  condition:
    $url
}


// Styx (Kein Edition) Exploit Kit (rule #3)
rule Styx_Kein_Edition_3 : Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /&t=17$/ nocase
  condition:
    $url
}
