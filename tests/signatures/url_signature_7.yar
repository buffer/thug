rule url_signature_7
{
  meta:
    domain_whitelist = "buffer.github.io"
  strings:
    $url1 = "https://buffer.github.io/thug/"
  condition:
    all of them
}
