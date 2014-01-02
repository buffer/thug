// CritXPack Exploit Kit (rule #1)
rule CritXPack_1 : JAR Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /\/j[\d]{2}\.php\?i\=[A-Za-z0-9]{72,}\s/ nocase
  condition:
    $url
}


// CritXPack Exploit Kit (rule #2)
rule CritXPack_2 : EXE Exploit_Kit
{
  meta:
    author = "https://twitter.com/malc0de"
  strings:
    $url = /load\.php\?e\=[a-f0-9\%]{12,16}\&jquery\=[a-f0-9\%]{12,35}\&/ nocase
  condition:
    $url
}


// CritXPack Exploit Kit (rule #3)
rule CritXPack_3 : Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/[a-z][0-9]{6}[a-z]\// nocase
  condition:
    $url
}
