rule url_signature_3
{
  meta:
    domain_whitelist = "honeynet.org"
  strings:
    $url1 = "www.antifork.org"
  condition:
    all of them
}
