// Neutrino Exploit Kit (rule #1)
rule Neutrino_1 : Landing Exploit_Kit
{
  meta:
    author = "MalwareSigs" 
  strings:
    $url = /\/[a-z]{4,14}\?[a-z]{8,9}=[0-9]{7}$/ nocase
  condition:
    $url
}


// Neutrino Exploit Kit (rule #2)
rule Neutrino_2 : Exploit_or_EXE Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /=[a-f0-9]{24}$/ nocase
  condition:
    $url
}


// Neutrino Exploit Kit (rule #3)
rule Neutrino_3 : Exploit_or_EXE Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[A-Za-z0-9]{50,}(==\?)\?$/ nocase
  condition:
    $url
}


// Neutrino Exploit Kit (rule #4)
rule Neutrino_4 : EXE Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /\/[a-z]{4,15}\?[a-z]{4,7}\=[a-f0-9]{24}/ nocase
  condition:
    $url
}
