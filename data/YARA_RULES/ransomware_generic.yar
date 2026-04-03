/*
    قواعد YARA الشاملة لكشف برامج الفدية
    Enhanced Ransomware Detection Rules
    الإصدار 2.0.0
*/

rule Ransomware_Generic_Patterns {
    meta:
        description = "كشف الأنماط العامة لبرامج الفدية"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        version = "2.0"
        severity = "high"
        
    strings:
        // كلمات مفتاحية متعلقة بالفدية
        $decrypt1 = "DECRYPT" nocase
        $decrypt2 = "RANSOM" nocase
        $decrypt3 = "LOCKED" nocase
        $decrypt4 = "ENCRYPTED" nocase
        $decrypt5 = "RESTORE" nocase
        
        // عملات رقمية
        $bitcoin1 = "bitcoin" nocase
        $bitcoin2 = "BTC" nocase
        $bitcoin3 = "wallet" nocase
        $bitcoin4 = "cryptocurrency" nocase
        
        // طلب الدفع
        $payment1 = "payment" nocase
        $payment2 = "pay" nocase
        $payment3 = "money" nocase
        $payment4 = "price" nocase
        
        // امتدادات ملفات مشبوهة
        $ext1 = ".encrypted"
        $ext2 = ".locked"
        $ext3 = ".cry"
        $ext4 = ".vault"
        
        // رسائل الفدية
        $msg1 = "your files have been encrypted" nocase
        $msg2 = "all your files are encrypted" nocase
        $msg3 = "files have been locked" nocase
        $msg4 = "decrypt your files" nocase
        
    condition:
        3 of ($decrypt*) or 
        2 of ($bitcoin*) or 
        3 of ($payment*) or 
        any of ($ext*) or 
        any of ($msg*)
}

rule Ransomware_File_Extensions {
    meta:
        description = "كشف امتدادات ملفات برامج الفدية المعروفة"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        severity = "critical"
        
    strings:
        // امتدادات WannaCry
        $ext1 = ".WANNACRY"
        $ext2 = ".WCRY"
        $ext3 = ".WNCRY"
        
        // امتدادات Locky
        $ext4 = ".LOCKY"
        $ext5 = ".ZEPTO"
        $ext6 = ".ODIN"
        $ext7 = ".THOR"
        
        // امتدادات Cerber
        $ext8 = ".CERBER"
        $ext9 = ".CERBER2"
        $ext10 = ".CERBER3"
        
        // امتدادات أخرى شائعة
        $ext11 = ".CRYPTO"
        $ext12 = ".ENCRYPTED"
        $ext13 = ".LOCKED"
        $ext14 = ".VAULT"
        $ext15 = ".MICRO"
        $ext16 = ".DHARMA"
        $ext17 = ".SAGE"
        $ext18 = ".GLOBE"
        $ext19 = ".PURGE"
        $ext20 = ".CRYPTOWALL"
        
    condition:
        any of them
}

rule Ransomware_Encryption_Patterns {
    meta:
        description = "كشف أنماط التشفير المستخدمة في برامج الفدية"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        severity = "high"
        
    strings:
        // مكتبات التشفير
        $crypto1 = "CryptEncrypt" nocase
        $crypto2 = "CryptDecrypt" nocase
        $crypto3 = "CryptGenKey" nocase
        $crypto4 = "CryptCreateHash" nocase
        
        // خوارزميات التشفير
        $algo1 = "AES" nocase
        $algo2 = "RSA" nocase
        $algo3 = "DES" nocase
        $algo4 = "3DES" nocase
        $algo5 = "Blowfish" nocase
        
        // عمليات الملفات المشبوهة
        $file1 = "DeleteFile" nocase
        $file2 = "MoveFile" nocase
        $file3 = "CopyFile" nocase
        $file4 = "CreateFile" nocase
        
    condition:
        2 of ($crypto*) and 1 of ($algo*) and 2 of ($file*)
}

rule Ransomware_Registry_Modifications {
    meta:
        description = "كشف تعديلات السجل المرتبطة ببرامج الفدية"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        severity = "medium"
        
    strings:
        // مفاتيح السجل المشبوهة
        $reg1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg3 = "HKEY_CURRENT_USER\\Control Panel\\Desktop\\Wallpaper" nocase
        
        // عمليات السجل
        $regop1 = "RegSetValueEx" nocase
        $regop2 = "RegCreateKey" nocase
        $regop3 = "RegOpenKey" nocase
        
    condition:
        1 of ($reg*) and 1 of ($regop*)
}

rule Ransomware_Network_Activity {
    meta:
        description = "كشف النشاط الشبكي المشبوه لبرامج الفدية"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        severity = "medium"
        
    strings:
        // عناوين IP مشبوهة (TOR)
        $tor1 = ".onion" nocase
        
        // بروتوكولات شبكية
        $net1 = "HttpSendRequest" nocase
        $net2 = "InternetConnect" nocase
        $net3 = "WinHttpConnect" nocase
        
        // عمليات التحميل
        $download1 = "URLDownloadToFile" nocase
        $download2 = "DownloadFile" nocase
        
    condition:
        1 of ($tor*) or (1 of ($net*) and 1 of ($download*))
}

rule Ransomware_Process_Behavior {
    meta:
        description = "كشف سلوك العمليات المشبوه لبرامج الفدية"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        severity = "high"
        
    strings:
        // إنهاء العمليات
        $proc1 = "TerminateProcess" nocase
        $proc2 = "ExitProcess" nocase
        
        // إيقاف الخدمات
        $svc1 = "ControlService" nocase
        $svc2 = "OpenService" nocase
        $svc3 = "StopService" nocase
        
        // حذف الملفات
        $del1 = "DeleteFile" nocase
        $del2 = "RemoveDirectory" nocase
        
        // تعديل الوقت
        $time1 = "SetFileTime" nocase
        $time2 = "GetSystemTime" nocase
        
    condition:
        2 of ($proc*) or 2 of ($svc*) or 2 of ($del*) or 1 of ($time*)
}

rule Ransomware_Anti_Analysis {
    meta:
        description = "كشف تقنيات مكافحة التحليل في برامج الفدية"
        author = "Enhanced Security Team"
        date = "2025-09-04"
        severity = "medium"
        
    strings:
        // كشف الآلات الافتراضية
        $vm1 = "VirtualBox" nocase
        $vm2 = "VMware" nocase
        $vm3 = "QEMU" nocase
        $vm4 = "Xen" nocase
        
        // كشف أدوات التحليل
        $debug1 = "IsDebuggerPresent" nocase
        $debug2 = "CheckRemoteDebuggerPresent" nocase
        $debug3 = "OutputDebugString" nocase
        
        // تقنيات التشويش
        $obf1 = "VirtualProtect" nocase
        $obf2 = "VirtualAlloc" nocase
        
    condition:
        1 of ($vm*) or 1 of ($debug*) or 1 of ($obf*)
}

