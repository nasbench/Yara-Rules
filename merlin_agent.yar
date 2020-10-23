rule icmpsh_reverse_shell
{
    meta:
        description = "Detects icmpsh reverse shell"
        author = "Nasreddine Bencherchali"
        reference = "https://github.com/inquisb/icmpsh"
        date = "2020-08-31"
        version = "0.1"
    strings:
        $s1 = "ICMP.DLL" nocase ascii wide
        $s2 = "iphlpapi.dll" nocase ascii wide
        $s3 = "icmp_create" fullword ascii wide
        $s4 = "icmp_send" fullword ascii wide
        $s5 = "transfer_icmp" fullword ascii wide
        $s6 = "create_icmp_channel" fullword ascii wide
        $s7 = "icmpsh-s.c" fullword ascii wide

    condition:
       ($s1 and $s2) and ($s3 or $s4 or $s5 or $s6 or $s7)
}
