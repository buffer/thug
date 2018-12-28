rule vbs_signature_6
{
  strings:
    $code1 = "MsgBox \"Hello, world\""
  condition:
    all of them
}
