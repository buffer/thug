// Fiesta Exploit Kit (rule #1)
rule Fiesta_1 : Landing Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-z0-9A-Z]{7}\/\?[0-9]$/ nocase
  condition:
    $url
}


// Fiesta Exploit Kit (rule #2)
rule Fiesta_2 : PDF_or_JAR_or_SWF Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-zA-Z0-9]{7}\/\?[0-9A-F]{50,}$/ nocase
  condition:
    $url
}


// Fiesta Exploit Kit (rule #3)
rule Fiesta_3 : EXE Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-zA-Z0-9]{7}\/\?[0-9A-F]{50,}(\;[0-9]){2}$/ nocase
  condition:
    $url
}


// Fiesta Exploit Kit (rule #4)
rule Fiesta_4 : EXE Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /\/\?[A-Za-z0-9]{55,70}\;\d+\;\d+/
  condition:
    $url
}


// Fiesta Exploit Kit (rule #5)
rule Fiesta_5 : Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /\/\?[A-Za-z0-9]{50,66}\;\d+\;\d+\;\d+/
  condition:
    $url
}
