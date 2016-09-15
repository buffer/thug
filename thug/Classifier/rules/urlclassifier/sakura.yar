// Sakura Exploit Kit (rule #1)
rule Sakura_1 : Exploit_Kit
{
  meta:
    author = "MalwareSigs"
  strings:
    $url = /:8[0-9]\/forum\/[a-z-_]+\.php$/
  condition:
    $url
}
