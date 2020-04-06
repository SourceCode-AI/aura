rule eicar_substring_test {
    meta:
        description = "Standard AV test, checking for an EICAR substring"
        author = "Austin Byers | Airbnb CSIRT"

    strings:
        $eicar_substring = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

    condition:
        all of them
}

rule SuspiciousFile: suspicious_file
{
    meta:
        score = 10
    strings:
        $pypi = /[^\s]\.pypirc['"]/ ascii wide
        $keepass1 = /\.kdbx\b/
        $keepass2 = /\.kdb\b/
    condition:
        any of them
}

rule PossiblePersistence: persistence
{
    meta:
        score = 20
    strings:
        $profile = "~/.profile"
        $bashrc = /\b\.bashrc/
    condition:
        any of them
}


//TO-DO: https://github.com/SublimeCodeIntel/CodeIntel/blob/master/codeintel/which.py#L101
rule RegistryKey: registry_key
{
    meta:
        score = 20
    strings:
        $pth = /\b(HKEY_LOCAL_MACHINE|HKLM|HKEY_USERS|HKEY_CURRENT_USER)[\\a-z\/\.-_]{5,}/ nocase
    condition:
        any of them
}

rule CryptoMiner: crypto_miner
{
    meta:
        score = 50
    strings:
        $a1 = "stratum+tcp://" ascii
        $a2 = "\"normalHashing\": true," ascii
        $a3 = "CoinHive.CONFIG.REQUIRES_AUTH" fullword ascii
        $a4 = "https://coin-hive.com/" ascii
        $a5 = /\bxmrig\b/ ascii
    condition:
        any of them
}

/*rule BitcoinAddr: bitcoin_address
{
    strings:
        $addr = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/
    condition:
        $addr
}*/


rule RSAKey: rsa_key
{
    strings:
        $header = /-----BEGIN[\w ]{,20}? (PUBLIC|PRIVATE) KEY-----.{20,}?-----END[\w ]{,20}? (PUBLIC|PRIVATE) KEY-----/
    condition:
        $header
}
