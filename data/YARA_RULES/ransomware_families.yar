/*
    قواعد YARA لعائلات برامج الفدية المعروفة
    Known Ransomware Families Detection Rules
*/

rule WannaCry_Ransomware {
    meta:
        description = "كشف برنامج الفدية WannaCry"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        family = "WannaCry"
        severity = "critical"
        
    strings:
        $s1 = "Wana Decrypt0r" nocase
        $s2 = "WANNACRY" nocase
        $s3 = "wcry@" nocase
        $s4 = ".WNCRY" nocase
        $s5 = "tasksche.exe"
        $s6 = "mssecsvc.exe"
        $s7 = "taskdl.exe"
        $s8 = "wannacry"
        
    condition:
        2 of them
}

rule Locky_Ransomware {
    meta:
        description = "كشف برنامج الفدية Locky"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        family = "Locky"
        severity = "critical"
        
    strings:
        $s1 = ".locky" nocase
        $s2 = ".zepto" nocase
        $s3 = ".odin" nocase
        $s4 = ".thor" nocase
        $s5 = "_Locky_recover_instructions.txt"
        $s6 = "DECRYPT_INSTRUCTIONS"
        
    condition:
        any of them
}

rule Cerber_Ransomware {
    meta:
        description = "كشف برنامج الفدية Cerber"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        family = "Cerber"
        severity = "critical"
        
    strings:
        $s1 = ".cerber" nocase
        $s2 = ".cerber2" nocase
        $s3 = ".cerber3" nocase
        $s4 = "# DECRYPT MY FILES #"
        $s5 = "CerberDecryptor"
        
    condition:
        any of them
}

rule CryptoWall_Ransomware {
    meta:
        description = "كشف برنامج الفدية CryptoWall"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        family = "CryptoWall"
        severity = "critical"
        
    strings:
        $s1 = "DECRYPT_INSTRUCTION" nocase
        $s2 = "CryptoWall" nocase
        $s3 = "HELP_DECRYPT" nocase
        $s4 = ".cryptowall" nocase
        
    condition:
        any of them
}

rule TeslaCrypt_Ransomware {
    meta:
        description = "كشف برنامج الفدية TeslaCrypt"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        family = "TeslaCrypt"
        severity = "critical"
        
    strings:
        $s1 = ".vvv" nocase
        $s2 = ".ccc" nocase
        $s3 = ".zzz" nocase
        $s4 = ".abc" nocase
        $s5 = ".xyz" nocase
        $s6 = "RECOVERY_KEY" nocase
        $s7 = "TeslaCrypt" nocase
        
    condition:
        any of them
}

rule Petya_Ransomware {
    meta:
        description = "كشف برنامج الفدية Petya/NotPetya"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        family = "Petya"
        severity = "critical"
        
    strings:
        $s1 = "Petya" nocase
        $s2 = "NotPetya" nocase
        $s3 = "wowsmith123456@posteo.net"
        $s4 = "Your hard disk has been encrypted"
        $s5 = "CHKDSK is repairing sector"
        
    condition:
        any of them
}

rule BadRabbit_Ransomware {
    meta:
        description = "كشف برنامج الفدية Bad Rabbit"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        family = "BadRabbit"
        severity = "critical"
        
    strings:
        $s1 = "Bad Rabbit" nocase
        $s2 = "caforssztxqzf2nm.onion"
        $s3 = "dispci.exe"
        $s4 = "cscc.dat"
        
    condition:
        any of them
}

rule GandCrab_Ransomware {
    meta:
        description = "كشف برنامج الفدية GandCrab"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        family = "GandCrab"
        severity = "critical"
        
    strings:
        $s1 = "GANDCRAB" nocase
        $s2 = ".GDCB" nocase
        $s3 = ".CRAB" nocase
        $s4 = "KRAB-DECRYPT.txt"
        $s5 = "gandcrab" nocase
        
    condition:
        any of them
}

rule Ryuk_Ransomware {
    meta:
        description = "كشف برنامج الفدية Ryuk"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        family = "Ryuk"
        severity = "critical"
        
    strings:
        $s1 = "RYUK" nocase
        $s2 = "RyukReadMe.txt"
        $s3 = ".ryk" nocase
        $s4 = "Ryuk" nocase
        $s5 = "No system is safe"
        
    condition:
        any of them
}

rule Maze_Ransomware {
    meta:
        description = "كشف برنامج الفدية Maze"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        family = "Maze"
        severity = "critical"
        
    strings:
        $s1 = "MAZE" nocase
        $s2 = "maze" nocase
        $s3 = "DECRYPT-FILES.txt"
        $s4 = "Your network has been penetrated"
        
    condition:
        any of them
}

rule Sodinokibi_Ransomware {
    meta:
        description = "كشف برنامج الفدية Sodinokibi/REvil"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        family = "Sodinokibi"
        severity = "critical"
        
    strings:
        $s1 = "Sodinokibi" nocase
        $s2 = "REvil" nocase
        $s3 = "{random}-readme.txt"
        $s4 = "aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion"
        
    condition:
        any of them
}

rule Conti_Ransomware {
    meta:
        description = "كشف برنامج الفدية Conti"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        family = "Conti"
        severity = "critical"
        
    strings:
        $s1 = "CONTI" nocase
        $s2 = "conti" nocase
        $s3 = "readme.txt"
        $s4 = "All of your files are currently encrypted"
        $s5 = ".conti" nocase
        
    condition:
        any of them
}

rule DarkSide_Ransomware {
    meta:
        description = "كشف برنامج الفدية DarkSide"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        family = "DarkSide"
        severity = "critical"
        
    strings:
        $s1 = "DarkSide" nocase
        $s2 = "darkside" nocase
        $s3 = "README.{id}.TXT"
        $s4 = "darksidedxcftmqa.onion"
        
    condition:
        any of them
}

