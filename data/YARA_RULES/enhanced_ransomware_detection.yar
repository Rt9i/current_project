/*
قواعد YARA المحسنة لكشف برامج الفدية
Enhanced YARA Rules for Ransomware Detection
تم تطويرها بناءً على نتائج الاختبار
*/

rule Enhanced_Ransomware_Generic_Detection
{
    meta:
        description = "كشف عام محسن لبرامج الفدية"
        author = "Enhanced Protection System"
        date = "2025-09-04"
        version = "2.0"
        severity = "high"
        
    strings:
        // رسائل الفدية الشائعة
        $ransom_msg1 = "your files have been encrypted" nocase
        $ransom_msg2 = "all your files are encrypted" nocase
        $ransom_msg3 = "pay ransom" nocase
        $ransom_msg4 = "bitcoin payment" nocase
        $ransom_msg5 = "decryption key" nocase
        $ransom_msg6 = "contact us for" nocase
        $ransom_msg7 = "time limit" nocase
        $ransom_msg8 = "restore your files" nocase
        $ransom_msg9 = "recover your data" nocase
        $ransom_msg10 = "unlock your files" nocase
        
        // عناوين Bitcoin
        $bitcoin1 = /1[A-HJ-NP-Z0-9]{25,34}/
        $bitcoin2 = /3[A-HJ-NP-Z0-9]{25,34}/
        $bitcoin3 = /bc1[a-z0-9]{39,59}/
        
        // امتدادات مشبوهة كنصوص عامة
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase
        $ext3 = ".crypto" nocase
        $ext4 = ".crypt" nocase
        $ext5 = ".enc" nocase
        $ext6 = ".ransom" nocase
        $ext7 = ".vault" nocase
        $ext8 = ".secure" nocase
        
        // كلمات مفتاحية قد تظهر في الأسماء/المحتوى
        $filename1 = "decrypt" nocase
        $filename2 = "ransom" nocase
        $filename3 = "readme" nocase
        $filename4 = "how_to_decrypt" nocase
        $filename5 = "restore_files" nocase
        
    condition:
        // رسائل الفدية + عناوين Bitcoin
        (
            ($ransom_msg1 or $ransom_msg2 or $ransom_msg3 or $ransom_msg4 or $ransom_msg5 or
             $ransom_msg6 or $ransom_msg7 or $ransom_msg8 or $ransom_msg9 or $ransom_msg10)
            and
            ($bitcoin1 or $bitcoin2 or $bitcoin3)
        )
        or
        
        // امتدادات مشبوهة + رسائل
        (
            ($ext1 or $ext2 or $ext3 or $ext4 or $ext5 or $ext6 or $ext7 or $ext8)
            and
            ($ransom_msg1 or $ransom_msg2 or $ransom_msg3 or $ransom_msg4 or $ransom_msg5 or
             $ransom_msg6 or $ransom_msg7 or $ransom_msg8 or $ransom_msg9 or $ransom_msg10)
        )
        or
        
        // أسماء ملفات مشبوهة + محتوى مشبوه
        (
            ($filename1 or $filename2 or $filename3 or $filename4 or $filename5)
            and
            ($ransom_msg1 or $ransom_msg2 or $ransom_msg3 or $ransom_msg4 or $ransom_msg5 or
             $ransom_msg6 or $ransom_msg7 or $ransom_msg8 or $ransom_msg9 or $ransom_msg10)
        )
        or
        
        // عدة مؤشرات مشبوهة
        (
            (
                #ransom_msg1 + #ransom_msg2 + #ransom_msg3 + #ransom_msg4 + #ransom_msg5 +
                #ransom_msg6 + #ransom_msg7 + #ransom_msg8 + #ransom_msg9 + #ransom_msg10
            ) >= 3
        )
        or
        (
            (
                #bitcoin1 + #bitcoin2 + #bitcoin3
            ) >= 2
            and
            (
                #ransom_msg1 + #ransom_msg2 + #ransom_msg3 + #ransom_msg4 + #ransom_msg5 +
                #ransom_msg6 + #ransom_msg7 + #ransom_msg8 + #ransom_msg9 + #ransom_msg10
            ) >= 1
        )
}

rule Enhanced_Encrypted_File_Detection
{
    meta:
        description = "كشف الملفات المشفرة بواسطة برامج الفدية"
        author = "Enhanced Protection System"
        date = "2025-09-04"
        version = "2.0"
        severity = "high"
        
    strings:
        $crypt_header1 = "RANSOMWARE_ENCRYPTED:" ascii
        $crypt_header2 = "ENCRYPTED_FILE:" ascii
        $crypt_header3 = "LOCKED_BY:" ascii
        $crypt_header4 = { 52 41 4E 53 4F 4D } // "RANSOM"
        
        $base64_long = /[A-Za-z0-9+\/]{100,}={0,2}/ ascii
        $hex_long = /[0-9A-Fa-f]{200,}/ ascii
        
        $high_entropy = { ( 00 | FF ) [100-1000] ( 00 | FF ) }
        
    condition:
        // هيدر تشفير واضح
        ( $crypt_header1 or $crypt_header2 or $crypt_header3 or $crypt_header4 )
        or
        
        // ملف صغير مع محتوى مشفر
        ( filesize < 10240 and ( $base64_long or $hex_long ) )
        or
        
        // ملف متوسط مع أنماط تشفير متعددة
        ( filesize < 102400 and ( #base64_long >= 2 ) )
        or
        
        // ملف كبير مع بيانات عشوائية
        ( filesize >= 102400 and $high_entropy )
}

rule Enhanced_Ransomware_Behavior_Detection
{
    meta:
        description = "كشف السلوك المشبوه لبرامج الفدية"
        author = "Enhanced Protection System"
        date = "2025-09-04"
        version = "2.0"
        severity = "medium"
        
    strings:
        $crypto_func1 = "CryptEncrypt" ascii
        $crypto_func2 = "CryptDecrypt" ascii
        $crypto_func3 = "CryptGenKey" ascii
        $crypto_func4 = "AES_encrypt" ascii
        $crypto_func5 = "RSA_encrypt" ascii
        
        $file_op1 = "DeleteFile" ascii
        $file_op2 = "MoveFile" ascii
        $file_op3 = "CopyFile" ascii
        $file_op4 = "CreateFile" ascii
        
        $network1 = "InternetOpen" ascii
        $network2 = "HttpSendRequest" ascii
        $network3 = "WinHttpOpen" ascii
        
        $system1 = "RegSetValue" ascii
        $system2 = "RegDeleteKey" ascii
        $system3 = "ShellExecute" ascii
        
    condition:
        // وظائف التشفير + عمليات الملفات
        (
            ($crypto_func1 or $crypto_func2 or $crypto_func3 or $crypto_func4 or $crypto_func5)
            and
            ($file_op1 or $file_op2 or $file_op3 or $file_op4)
        )
        or
        
        // عمليات متعددة مشبوهة
        (
            (
                #crypto_func1 + #crypto_func2 + #crypto_func3 + #crypto_func4 + #crypto_func5
            ) >= 2
            and
            (
                #file_op1 + #file_op2 + #file_op3 + #file_op4
            ) >= 2
        )
        or
        
        // تشفير + شبكة + نظام
        (
            ($crypto_func1 or $crypto_func2 or $crypto_func3 or $crypto_func4 or $crypto_func5)
            and
            ($network1 or $network2 or $network3)
            and
            ($system1 or $system2 or $system3)
        )
}

rule Enhanced_Ransomware_Extensions_Detection
{
    meta:
        description = "كشف امتدادات برامج الفدية المعروفة والجديدة"
        author = "Enhanced Protection System"
        date = "2025-09-04"
        version = "2.0"
        severity = "high"
        
    condition:
        (filename matches /.*\.(wannacry|locky|cerber|cryptolocker|teslacrypt|cryptowall|reveton|petya|badrabbit|ryuk|maze|conti|darkside|lockbit|blackmatter|hive|alphv)$/i)
        or
        (filename matches /.*\.(locked|encrypted|crypto|crypt|enc|ransom|vault|secure|protected|coded|sealed)$/i)
        or
        (filename matches /.*\.[a-z]{2,4}\.(locked|encrypted|crypto|crypt|enc|ransom)$/i)
        or
        (filename matches /.*\.[a-z0-9]{6,}$/i)
}

rule Enhanced_Ransom_Note_Detection
{
    meta:
        description = "كشف ملفات رسائل الفدية"
        author = "Enhanced Protection System"
        date = "2025-09-04"
        version = "2.0"
        severity = "high"
        
    strings:
        $note_name1 = "README" nocase
        $note_name2 = "DECRYPT" nocase
        $note_name3 = "RANSOM" nocase
        $note_name4 = "HOW_TO" nocase
        $note_name5 = "RESTORE" nocase
        $note_name6 = "RECOVER" nocase
        $note_name7 = "UNLOCK" nocase
        $note_name8 = "PAYMENT" nocase
        
        $content1 = "Your files have been encrypted" nocase
        $content2 = "All your important files" nocase
        $content3 = "To decrypt your files" nocase
        $content4 = "Bitcoin address" nocase
        $content5 = "Payment must be made" nocase
        $content6 = "Do not rename" nocase
        $content7 = "Do not delete" nocase
        $content8 = "Contact us at" nocase
        $content9 = "Decryption key" nocase
        $content10 = "Time limit" nocase
        
        $format1 = "╔══════════════════════════════════════════════════════════════╗"
        $format2 = "████████████████████████████████████████████████████████████"
        $format3 = "=================================================="
        $format4 = "******************************************"
        
    condition:
        // اسم ملف مشبوه + محتوى رسالة فدية
        (
            ($note_name1 or $note_name2 or $note_name3 or $note_name4 or $note_name5 or
             $note_name6 or $note_name7 or $note_name8)
            and
            ($content1 or $content2 or $content3 or $content4 or $content5 or
             $content6 or $content7 or $content8 or $content9 or $content10)
        )
        or
        
        // تنسيق رسالة فدية + محتوى
        (
            ($format1 or $format2 or $format3 or $format4)
            and
            (
                #content1 + #content2 + #content3 + #content4 + #content5 +
                #content6 + #content7 + #content8 + #content9 + #content10
            ) >= 3
        )
        or
        
        // محتوى رسالة فدية قوي
        (
            #content1 + #content2 + #content3 + #content4 + #content5 +
            #content6 + #content7 + #content8 + #content9 + #content10
        ) >= 5
        or
        
        // ملف نصي صغير مع كلمات مفتاحية متعددة
        (
            filesize < 10240
            and
            (
                #content1 + #content2 + #content3 + #content4 + #content5 +
                #content6 + #content7 + #content8 + #content9 + #content10
            ) >= 3
        )
}

rule Enhanced_Crypto_Ransomware_Detection
{
    meta:
        description = "كشف برامج الفدية التي تستخدم التشفير المتقدم"
        author = "Enhanced Protection System"
        date = "2025-09-04"
        version = "2.0"
        severity = "critical"
        
    strings:
        $crypto_lib1 = "advapi32.dll" nocase
        $crypto_lib2 = "bcrypt.dll" nocase
        $crypto_lib3 = "ncrypt.dll" nocase
        $crypto_lib4 = "crypt32.dll" nocase
        
        $algo1 = "AES" ascii
        $algo2 = "RSA" ascii
        $algo3 = "ChaCha20" ascii
        $algo4 = "Salsa20" ascii
        $algo5 = "Blowfish" ascii
        
        $func1 = "BCryptEncrypt" ascii
        $func2 = "BCryptDecrypt" ascii
        $func3 = "BCryptGenerateSymmetricKey" ascii
        $func4 = "CryptAcquireContext" ascii
        $func5 = "CryptCreateHash" ascii
        
        $key_pattern1 = { 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F }
        $key_pattern2 = /[A-Fa-f0-9]{64}/ ascii
        $key_pattern3 = /[A-Za-z0-9+\/]{44}==/ ascii
        
    condition:
        // مكتبات تشفير + خوارزميات
        (
            ($crypto_lib1 or $crypto_lib2 or $crypto_lib3 or $crypto_lib4)
            and
            ($algo1 or $algo2 or $algo3 or $algo4 or $algo5)
        )
        or
        
        // وظائف تشفير متقدمة (عدّ صريح)
        (
            #func1 + #func2 + #func3 + #func4 + #func5
        ) >= 3
        or
        
        // أنماط مفاتيح + وظائف
        (
            ($key_pattern1 or $key_pattern2 or $key_pattern3)
            and
            ($func1 or $func2 or $func3 or $func4 or $func5)
        )
        or
        
        // تشفير متقدم + خوارزميات متعددة
        (
            (
                #algo1 + #algo2 + #algo3 + #algo4 + #algo5
            ) >= 2
            and
            (
                #func1 + #func2 + #func3 + #func4 + #func5
            ) >= 2
        )
}

rule Enhanced_Ransomware_Network_Activity
{
    meta:
        description = "كشف النشاط الشبكي المشبوه لبرامج الفدية"
        author = "Enhanced Protection System"
        date = "2025-09-04"
        version = "2.0"
        severity = "medium"
        
    strings:
        $url1 = ".onion" ascii
        $url2 = "tor2web" ascii
        $url3 = "darkweb" ascii
        
        $proto1 = "POST" ascii
        $proto2 = "PUT" ascii
        $proto3 = "CONNECT" ascii
        
        $ua1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" ascii
        $ua2 = "curl/" ascii
        $ua3 = "wget/" ascii
        
        $encrypted_data = /[A-Za-z0-9+\/]{100,}={0,2}/ ascii
        
    condition:
        // عناوين مشبوهة + بروتوكولات
        (
            ($url1 or $url2 or $url3)
            and
            ($proto1 or $proto2 or $proto3)
        )
        or
        
        // User Agents مشبوهة + بيانات مشفرة
        (
            ($ua1 or $ua2 or $ua3)
            and
            $encrypted_data
        )
        or
        
        // نشاط شبكي مكثف (عدّ صريح للبروتوكولات)
        (
            (#proto1 + #proto2 + #proto3) >= 2
            and
            $encrypted_data
        )
}

rule Enhanced_Ransomware_Persistence_Detection
{
    meta:
        description = "كشف آليات الثبات لبرامج الفدية"
        author = "Enhanced Protection System"
        date = "2025-09-04"
        version = "2.0"
        severity = "high"
        
    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii
        $reg3 = "SYSTEM\\CurrentControlSet\\Services" ascii
        
        $folder1 = "%APPDATA%" ascii
        $folder2 = "%TEMP%" ascii
        $folder3 = "%PROGRAMDATA%" ascii
        $folder4 = "\\Windows\\System32\\" ascii
        
        $system_file1 = "explorer.exe" ascii
        $system_file2 = "svchost.exe" ascii
        $system_file3 = "winlogon.exe" ascii
        
        $task1 = "schtasks" ascii
        $task2 = "at.exe" ascii
        $task3 = "TaskScheduler" ascii
        
    condition:
        // تعديل التسجيل + مجلدات النظام
        (
            ($reg1 or $reg2 or $reg3)
            and
            ($folder1 or $folder2 or $folder3 or $folder4)
        )
        or
        
        // استهداف ملفات النظام
        (
            ($system_file1 or $system_file2 or $system_file3)
            and
            ($folder1 or $folder2 or $folder3 or $folder4)
        )
        or
        
        // مهام مجدولة + ثبات
        (
            ($task1 or $task2 or $task3)
            and
            ($reg1 or $reg2 or $reg3)
        )
}

rule Enhanced_Test_Ransomware_Detection
{
    meta:
        description = "كشف فيروس الفدية الاختباري المستخدم في التقييم"
        author = "Enhanced Protection System"
        date = "2025-09-04"
        version = "2.0"
        severity = "critical"
        reference = "Test ransomware for system evaluation"
        
    strings:
        $test_sig1 = "AdvancedRansomwareTest" ascii
        $test_sig2 = "RANSOMWARE_ENCRYPTED:" ascii
        $test_sig3 = "advanced_ransomware_test.py" ascii
        $test_sig4 = "Test ID:" ascii
        $test_sig5 = "Decryption Key ID:" ascii
        
        $test_msg1 = "This is a TEST RANSOMWARE" ascii
        $test_msg2 = "for security system evaluation" ascii
        $test_msg3 = "No real harm intended" ascii
        $test_msg4 = "controlled test environment" ascii
        
        $test_pattern1 = ".LOCKED" ascii
        $test_pattern2 = "Fernet" ascii
        $test_pattern3 = "cryptography.fernet" ascii
        
        $test_file1 = "DECRYPT_YOUR_FILES.txt" ascii
        $test_file2 = "HOW_TO_DECRYPT.txt" ascii
        $test_file3 = "RANSOM_NOTE.txt" ascii
        $test_file4 = "README_DECRYPT.txt" ascii
        
    condition:
        // توقيعات الفيروس الاختباري
        ( $test_sig1 or $test_sig2 or $test_sig3 or $test_sig4 or $test_sig5 )
        or
        
        // رسائل الاختبار
        ( $test_msg1 or $test_msg2 or $test_msg3 or $test_msg4 )
        or
        
        // أنماط الاختبار + ملفات
        (
            ($test_pattern1 or $test_pattern2 or $test_pattern3)
            and
            ($test_file1 or $test_file2 or $test_file3 or $test_file4)
        )
        or
        
        // وجود اسمين مختلفين من ملفات الفدية الاختبارية (بدون استخدام "of")
        (
            ($test_file1 and $test_file2) or
            ($test_file1 and $test_file3) or
            ($test_file1 and $test_file4) or
            ($test_file2 and $test_file3) or
            ($test_file2 and $test_file4) or
            ($test_file3 and $test_file4)
        )
}
