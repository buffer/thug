rule url_signature_3
{
  meta:
    domain_whitelist = "honeynet.org"
  strings:
    $url1 = "www.honeynet.org"
  condition:
    all of them
}
