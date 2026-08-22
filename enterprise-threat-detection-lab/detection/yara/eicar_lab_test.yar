/* Authorized-lab only: detects the harmless EICAR antivirus test string. */
rule Lab_EICAR_Test_File
{
  meta:
    description = "Detects the benign EICAR antivirus test artifact in this lab"
    author = "Enterprise Threat Detection Lab"
    scope = "authorized-lab"
  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  condition:
    $eicar
}
