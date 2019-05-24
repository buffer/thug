rule html_signature_12
{
  meta:
    domain_whitelist = "antifork.org"
  strings:
    $html = "buffer homepage"
  condition:
    all of them
}
