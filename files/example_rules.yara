rule base64 : base64
{
    meta:
        description = "Base64 encoded blob"
    strings:
        $a = /([A-Za-z0-9+\/]{4}){12,}([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\b/
    condition:
        $a
}

rule SuspiciousFile: suspicious_file
{
    meta:
        score = 10
    strings:
        $ssh_priv_rsa = ".ssh/id_rsa"
        $pypi = /[^\s]\.pypirc['"]/ ascii wide
        $bash_hist = ".bash_history"
    condition:
        any of them
}
