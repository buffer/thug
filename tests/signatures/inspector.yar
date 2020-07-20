rule OnlineID
{
  strings:
    $s1 = "Online ID" nocase
  condition:
    all of them
}
