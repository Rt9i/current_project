rule example_malware_string
{
    meta:
        author = "Manus AI"
        date = "2025-08-13"
        description = "Simple YARA rule to detect a specific string often found in malware."
    strings:
        $a = "This is a malicious string"
        $b = "MalwareDetected"
    condition:
        $a or $b
}

rule detect_evil_exe
{
    meta:
        author = "Manus AI"
        date = "2025-08-13"
        description = "Detects a file named evil.exe"
    strings:
        $filename = "evil.exe" ascii wide
    condition:
        $filename
}


