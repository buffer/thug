rule sample_signature_10
{
  strings:
    $code1 = "VirtualQuery"
  condition:
    all of them
}
