rule eicar_substring_test {
    meta:
        description = "Standard AV test, checking for an EICAR substring"
        author = "Austin Byers | Airbnb CSIRT"

    strings:
        $eicar_substring = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

    condition:
        all of them
}


rule SuspiciousStrings: suspicious_strings
{
    meta:
        score = 10
        score_each = true
    strings:
        $str1 = "SecEdit"
        $str2 = "searchfilterhost"
        $str3 = "WUDFPort"
        $str4 = "MSASTUIL"
        $str5 = "WmiPrvSE"
        $str6 = "wmic process"
        $str7 = "keylogger" ascii nocase
        $str8 = "whoami"
        $str9 = "VIAddVersionKey"  // Version information for nsis keys
        $str10 = "makensis.exe"
        $str11 = "defaults write"  // MacOS changing defaults
        $str12 = "com.apple.loginwindow"  // MacOS login service
        $str13 = "/etc/init.d/"
        $str14 = "ui.promptforcredential"
        $str15 = "[Environment]::UserName"  // powershell
        $str16 = "[Environment]::UserDomainName"  // powershell
        $str17 = "osascript -e"
        $str18 = "Taskkill"
        $str19 = "rundll32"
        $str20 = "kextstat"  // macos alternative of lsmod. Display status of loaded kernel extensions (kexts)
        $str21 = "lsmod"
        $str22 = "DisableAntiSpyware"  // Windows Defender
        $str23 = "wevtutil"  // windows eventlog
        $str24 = "DataExecutionPrevention_SupportPolicy"
        $str25 = "EnableLUA"  // Windows UAC
        $str26 = "DisableAntiSpyware"  // MS defender
        $str27 = "pmset displaysleepnow"  // Mac turn of display
        $str28 = "xset dpms force off"  // Linux turn of display
        $str29 = "/var/db/dslocal/nodes/Default/users/"  // OSX Location of hashes
        $str30 = "attrib +H"  // Hide file on windows
        $str31 = "chflags hidden"  // hide file on mac
        $str32 = "vlock"  // Lock screen on linux
        $str33 = "User.menu/Contents/Resources/CGSession -suspend"  // Lock screen on mac
        $str34 = "netsh wlan show profiles"  // geting wlan keys
    condition:
        any of them
}


rule DeterminingIP: determining_ip
{
    meta:
        score = 50
    strings:
        $s1 = "api.ipify.org"
        $s2 = "freegeoip.net"
        $s3 = "ipconfig.me"
        $s4 = "whatismyip.com"
    condition:
        any of them
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


/*rule SecretsLeak: secrets_leak
{
    meta:
        score = 100
    strings:
        $aws_secret_key = /aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]/ nocase
        $github = /github(.{0,20})?[0-9a-zA-Z]{35,40}/ nocase
        $linkedin_client_id = /linkedin(.{0,20})?[0-9a-z]{12}/ nocase
        $linkedin_secret_key = /linkedin(.{0,20})?[0-9a-z]{16}/ nocase
        $slack = /xox(b|a|p|r|s)-([0-9a-z]{10,48})?/ nocase
        $google_gcp_account = /"type": "service_account"/
        $heroku_api_key = /heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ nocase
        $sendgrid_api_key = /SG\.[\w_]{16,32}\.[\w_]{16,64}/
        $slack_webhook = /https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/
    condition:
        any of them
}*/


//TO-DO: https://github.com/SublimeCodeIntel/CodeIntel/blob/master/codeintel/which.py#L101
rule RegistryKey: registry_key
{
    meta:
        score = 20
    strings:
        $pth = /(HKEY_LOCAL_MACHINE|HKLM|HKEY_USERS|HKEY_CURRENT_USER|SOFTWARE|SYSTEM)((\\{1,2}|\/)[a-z\.-_ ]{5,})+/ nocase wide ascii
        $autorun = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
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


rule WindowsExecutable: windows_executable
{
    condition:
        // MZ and PE header
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}


rule WindowsExecutable2: windows_executable
{
    strings:
        $a = "This program cannot" xor
    condition:
        $a
}


rule ChromePath: chrome_path
{
    strings:
        $s1 = "\\Google\\Chrome\\User Data\\Default\\"
        $s2 = "/Library/Application Support/Google/Chrome/Default/"
        $s3 = "/.config/google-chrome/Default/"
    condition:
        any of them
}


rule meterpreter_reverse_tcp_shellcode {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Rule for metasploit's  meterpreter reverse tcp raw shellcode"

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s3 = { 4c77 2607 }             // kernel32 checksum
        $s4 = "ws2_"                    // ws2_32.dll
        $s5 = { 2980 6b00 }             // WSAStartUp checksum
        $s6 = { ea0f dfe0 }             // WSASocket checksum
        $s7 = { 99a5 7461 }             // connect checksum

    condition:
        all of them and filesize < 5KB
}

rule meterpreter_reverse_tcp_shellcode_rev1 {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Meterpreter reverse TCP shell rev1"
        LHOST = 0xae
        LPORT = 0xb5

    strings:
        $s1 = { 6a00 53ff d5 }

    condition:
        meterpreter_reverse_tcp_shellcode and $s1 in (270..filesize)
}

rule meterpreter_reverse_tcp_shellcode_rev2 {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Meterpreter reverse TCP shell rev2"
        LHOST = 194
        LPORT = 201

    strings:
        $s1 = { 75ec c3 }

    condition:
        meterpreter_reverse_tcp_shellcode and $s1 in (270..filesize)
}

rule meterpreter_reverse_tcp_shellcode_domain {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Variant used if the user specifies a domain instead of a hard-coded IP"

    strings:
        $s1 = { a928 3480 }             // Checksum for gethostbyname
        $domain = /(\w+\.)+\w{2,6}/

    condition:
        meterpreter_reverse_tcp_shellcode and all of them
}

rule metasploit_download_exec_shellcode_rev1 {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's download and exec shellcode"
        name = "Metasploit download & exec payload"
        URL = 185

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s4 = { 4c77 2607 }             // checksum for LoadLibraryA
        $s5 = { 3a56 79a7 }             // checksum for InternetOpenA
        $s6 = { 5789 9fc6 }             // checksum for InternetConnectA
        $s7 = { eb55 2e3b }             // checksum for HTTPOpenRequestA
        $s8 = { 7546 9e86 }             // checksum for InternetSetOptionA
        $s9 = { 2d06 187b }             // checksum for HTTPSendRequestA
        $url = /\/[\w_\-\.]+/

    condition:
        all of them and filesize < 5KB
}

rule metasploit_download_exec_shellcode_rev2 {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's download and exec shellcode"
        name = "Metasploit download & exec payload"
        URL = 185

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s4 = { 4c77 2607 }             // checksum for LoadLibraryA
        $s5 = { 3a56 79a7 }             // checksum for InternetOpenA
        $s6 = { 5789 9fc6 }             // checksum for InternetConnectA
        $s7 = { eb55 2e3b }             // checksum for HTTPOpenRequestA
        $s9 = { 2d06 187b }             // checksum for HTTPSendRequestA
        $url = /\/[\w_\-\.]+/

    condition:
        all of them and filesize < 5KB
}

rule metasploit_bind_shell {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's bind shell shellcode"
        name = "Metasploit bind shell payload"

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s3 = { 4c77 2607 }             // checksum for LoadLibraryA
        $s4 = { 2980 6b00 }             // checksum for WSAStartup
        $s5 = { ea0f dfe0 }             // checksum for WSASocketA
        $s6 = { c2db 3767 }             // checksum for bind
        $s7 = { b7e9 38ff }             // checksum for listen
        $s8 = { 74ec 3be1 }             // checksum for accept

    condition:
        all of them and filesize < 5KB
}
