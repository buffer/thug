// Impact Exploit Kit (rule #1)
rule Impact_1 : EXE Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /\/\w+\.php\?\;\d/ nocase
  condition:
    $url
}


// Impact Exploit Kit (rule #2)
rule Impact_2 : Landing Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-z]{8}\.php\?[a-z]{8}=[0-9]{6}$/ nocase
  condition:
    $url
}
