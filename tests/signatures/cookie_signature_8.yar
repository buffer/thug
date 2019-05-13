rule cookie_signature_8
{
  strings:
    $cookie = "foo="
  condition:
    all of them
}
