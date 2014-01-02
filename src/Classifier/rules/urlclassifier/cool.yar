// Cool Exploit Kit (rule #1)
rule Cool_1 : Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /\/(world|read|news)\/([a-z]+(-|_)){1,}[a-z]+\.[a-z]{3,4}$/ nocase
  condition:
    $url
}


// Cool Exploit Kit (rule #2)
rule Cool_2 : Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /^http:\/\/[a-z0-9]{10,}\.[a-z0-9.\-]{6,}\/(read|news|world)\// nocase
  condition:
    $url
}
