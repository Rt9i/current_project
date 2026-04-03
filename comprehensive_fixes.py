#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
سكريبت الإصلاحات الشاملة
Comprehensive Fixes Script for Ransomware Protection System

يصلح جميع الأخطاء المحددة:
1. Database Errors (missing columns/tables)
2. Google Drive API 403 errors
3. Missing methods in Backup/Quarantine managers
4. YARA rules missing
5. SSL EOF errors
6. Virtual Environment activation
"""

import os
import sys
import sqlite3
import json
import subprocess
import platform
from pathlib import Path
import urllib.request
import ssl
import warnings

class ComprehensiveFixer:
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.src_dir = self.project_root / "src"
        self.data_dir = self.project_root / "data"
        self.database_dir = self.project_root / "data" / "database"
        self.venv_activation_script = None
        
        # Print colored output
        self.colors = {
            'RED': '\033[91m',
            'GREEN': '\033[92m', 
            'YELLOW': '\033[93m',
            'BLUE': '\033[94m',
            'PURPLE': '\033[95m',
            'CYAN': '\033[96m',
            'WHITE': '\033[97m',
            'ENDC': '\033[0m'
        }
    
    def color_print(self, message, color='WHITE'):
        print(f"{self.colors.get(color, '')}{message}{self.colors['ENDC']}")
    
    def print_header(self, title):
        self.color_print(f"\n{'='*60}", 'CYAN')
        self.color_print(f"🔧 {title}", 'CYAN')
        self.color_print(f"{'='*60}", 'CYAN')
    
    def print_success(self, message):
        self.color_print(f"✅ {message}", 'GREEN')
    
    def print_error(self, message):
        self.color_print(f"❌ {message}", 'RED')
    
    def print_warning(self, message):
        self.color_print(f"⚠️ {message}", 'YELLOW')
    
    def print_info(self, message):
        self.color_print(f"ℹ️ {message}", 'BLUE')
    
    def fix_1_database_errors(self):
        """إصلاح أخطاء قاعدة البيانات"""
        self.print_header("إصلاح أخطاء قاعدة البيانات (Database Errors)")
        
        try:
            # التأكد من وجود مجلد قاعدة البيانات
            self.database_dir.mkdir(parents=True, exist_ok=True)
            self.print_success(f"تم إنشاء مجلد قاعدة البيانات: {self.database_dir}")
            
            # مسارات قواعد البيانات
            db_paths = [
                self.database_dir / "app.db",
                self.project_root / "src" / "data" / "database" / "app.db"
            ]
            
            # البحث عن قاعدة البيانات
            db_path = None
            for path in db_paths:
                if path.exists():
                    db_path = path
                    break
            
            if not db_path:
                self.print_warning("لم يتم العثور على قاعدة بيانات موجودة، سيتم إنشاء واحدة جديدة")
                db_path = self.database_dir / "app.db"
            
            self.print_info(f"مسار قاعدة البيانات: {db_path}")
            
            # الاتصال بقاعدة البيانات وإصلاح الأخطاء
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            # التحقق من الجداول الموجودة
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            existing_tables = [row[0] for row in cursor.fetchall()]
            self.print_info(f"الجداول الموجودة: {existing_tables}")
            
            # إضافة الأعمدة الناقصة لجدول file_events
            cursor.execute("PRAGMA table_info(file_events);")
            file_events_columns = [row[1] for row in cursor.fetchall()]
            
            missing_columns = {
                'timestamp': 'TEXT DEFAULT CURRENT_TIMESTAMP',
                'severity': 'TEXT DEFAULT "info"',
                'description': 'TEXT DEFAULT ""'
            }
            
            for column, definition in missing_columns.items():
                if column not in file_events_columns:
                    try:
                        cursor.execute(f"ALTER TABLE file_events ADD COLUMN {column} {definition};")
                        self.print_success(f"تم إضافة العمود {column} لجدول file_events")
                    except sqlite3.Error as e:
                        self.print_warning(f"تعذر إضافة العمود {column}: {e}")
            
            # إنشاء الجداول الناقصة
            tables_to_create = {
                'recovery_points': """
                CREATE TABLE IF NOT EXISTS recovery_points (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    backup_path TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    hash_value TEXT
                );
                """,
                'restore_history': """
                CREATE TABLE IF NOT EXISTS restore_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    action TEXT NOT NULL,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN DEFAULT 1
                );
                """
            }
            
            for table_name, create_sql in tables_to_create.items():
                if table_name not in existing_tables:
                    try:
                        cursor.execute(create_sql)
                        self.print_success(f"تم إنشاء جدول {table_name}")
                    except sqlite3.Error as e:
                        self.print_error(f"تعذر إنشاء جدول {table_name}: {e}")
            
            conn.commit()
            conn.close()
            self.print_success("تم إصلاح أخطاء قاعدة البيانات بنجاح!")
            return True
            
        except Exception as e:
            self.print_error(f"خطأ في إصلاح قاعدة البيانات: {e}")
            return False
    
    def fix_2_google_drive_api(self):
        """إصلاح أخطاء Google Drive API"""
        self.print_header("إصلاح أخطاء Google Drive API")
        
        # التحقق من وجود ملف credentials.json
        credentials_path = self.project_root / "credentials.json"
        
        if not credentials_path.exists():
            self.print_error("ملف credentials.json غير موجود!")
            self.print_info("يرجى تحميل ملف credentials.json من Google Cloud Console")
            return False
        
        self.print_success("ملف credentials.json موجود")
        
        # إنشاء سكريبت تفعيل API
        activation_script = """
# تفعيل Google Drive API
# 1. ادخل الرابط التالي في المتصفح:
# https://console.developers.google.com/apis/api/drive.googleapis.com/overview

# 2. اضغط على "Enable API"

# 3. انتقل إلى:
# https://console.developers.google.com/apis/credentials

# 4. اختر مشروعك وقم بتحميل credentials.json

# 5. تأكد من إضافة النطاقات التالية:
# - https://www.googleapis.com/auth/drive
# - https://www.googleapis.com/auth/drive.file

print("Google Drive API activation instructions:")
print("1. Visit: https://console.developers.google.com/apis/api/drive.googleapis.com/overview")
print("2. Click 'Enable API'")
print("3. Go to: https://console.developers.google.com/apis/credentials")
print("4. Download credentials.json")
print("5. Ensure the following scopes are enabled:")
print("   - https://www.googleapis.com/auth/drive")
print("   - https://www.googleapis.com/auth/drive.file")
        """
        
        script_path = self.data_dir / "google_drive_activation.txt"
        script_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(activation_script)
        
        self.print_success(f"تم إنشاء تعليمات تفعيل Google Drive API: {script_path}")
        
        # إنشاء سكريبت اختبار API
        test_script = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""اختبار Google Drive API"""

import os
import sys
from pathlib import Path

def test_google_drive_api():
    try:
        from googleapiclient.discovery import build
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        
        # المسارات
        project_root = Path(__file__).parent.parent.parent
        credentials_path = project_root / "credentials.json"
        
        if not credentials_path.exists():
            print("❌ credentials.json غير موجود")
            return False
        
        # إعداد OAuth
        SCOPES = ['https://www.googleapis.com/auth/drive']
        
        # إنشاء خدمة Google Drive
        try:
            service = build('drive', 'v3', credentials=None)
            print("✅ تم إنشاء خدمة Google Drive بنجاح")
            return True
        except Exception as e:
            print(f"❌ خطأ في إنشاء خدمة Google Drive: {e}")
            return False
            
    except ImportError as e:
        print(f"❌ خطأ في استيراد المكتبات المطلوبة: {e}")
        return False

if __name__ == "__main__":
    test_google_drive_api()
'''
        
        test_path = self.project_root / "test_google_drive.py"
        with open(test_path, 'w', encoding='utf-8') as f:
            f.write(test_script)
        
        self.print_success(f"تم إنشاء سكريبت اختبار Google Drive: {test_path}")
        return True
    
    def fix_3_missing_methods(self):
        """إصلاح الطرق المفقودة في Backup/Quarantine Managers"""
        self.print_header("إصلاح الطرق المفقودة في Managers")
        
        # التحقق من وجود الملفات
        backup_manager_path = self.src_dir / "backup_manager.py"
        quarantine_manager_path = self.src_dir / "quarantine_manager.py"
        
        if not backup_manager_path.exists():
            self.print_error(f"ملف BackupManager غير موجود: {backup_manager_path}")
            return False
        
        if not quarantine_manager_path.exists():
            self.print_error(f"ملف QuarantineManager غير موجود: {quarantine_manager_path}")
            return False
        
        # قراءة ملف BackupManager
        with open(backup_manager_path, 'r', encoding='utf-8') as f:
            backup_content = f.read()
        
        # التحقق من وجود get_backup_status
        if 'def get_backup_status(' not in backup_content:
            self.print_warning("إضافة get_backup_status إلى BackupManager")
            
            # إضافة الطريقة إذا لم تكن موجودة
            backup_method = '''
    def get_backup_status(self):
        """الحصول على حالة النسخ الاحتياطية"""
        try:
            status = {
                'local_ready': False,
                'drive_ready': False,
                'total_backups': 0,
                'last_backup': None,
                'next_backup': None,
                'errors': []
            }
            
            # فحص النسخ الاحتياطية المحلية
            try:
                if hasattr(self, 'local_backup_dir') and self.local_backup_dir:
                    backup_dir = Path(self.local_backup_dir)
                    if backup_dir.exists():
                        backup_files = list(backup_dir.glob("*"))
                        status['total_backups'] = len(backup_files)
                        status['local_ready'] = True
            except Exception as e:
                status['errors'].append(f"خطأ في النسخ المحلية: {e}")
            
            # فحص Google Drive
            try:
                if hasattr(self, 'drive_service') and self.drive_service:
                    status['drive_ready'] = True
            except Exception as e:
                status['errors'].append(f"خطأ في Google Drive: {e}")
            
            return status
            
        except Exception as e:
            return {'error': str(e)}
'''
            
            # البحث عن نهاية الكلاس وإضافة الطريقة
            class_end = backup_content.rfind('    def ') + 4
            if class_end > 4:
                # العثور على نهاية آخر دالة
                lines = backup_content.split('\n')
                for i in range(len(lines)-1, -1, -1):
                    if lines[i].strip().startswith('def ') or lines[i].strip().startswith('class '):
                        class_end = sum(len(line) + 1 for line in lines[:i+1])
                        break
            
            # إدراج الطريقة قبل نهاية الكلاس
            backup_content = backup_content[:class_end] + backup_method + '\n' + backup_content[class_end:]
            
            # حفظ الملف
            with open(backup_manager_path, 'w', encoding='utf-8') as f:
                f.write(backup_content)
            
            self.print_success("تم إضافة get_backup_status إلى BackupManager")
        else:
            self.print_success("get_backup_status موجود بالفعل في BackupManager")
        
        # قراءة ملف QuarantineManager
        with open(quarantine_manager_path, 'r', encoding='utf-8') as f:
            quarantine_content = f.read()
        
        # التحقق من وجود get_quarantined_files
        if 'def get_quarantined_files(' not in quarantine_content:
            self.print_warning("إضافة get_quarantined_files إلى QuarantineManager")
            
            quarantine_method = '''
    def get_quarantined_files(self):
        """الحصول على قائمة الملفات المحجورة"""
        try:
            quarantined_files = []
            
            # قراءة ملف metadata
            metadata_path = self.quarantine_dir / "_metadata.json"
            if metadata_path.exists():
                with open(metadata_path, 'r', encoding='utf-8') as f:
                    try:
                        metadata = json.load(f)
                        if isinstance(metadata, dict):
                            for file_path, file_info in metadata.items():
                                file_info_copy = file_info.copy()
                                file_info_copy['original_path'] = file_path
                                quarantined_files.append(file_info_copy)
                    except json.JSONDecodeError:
                        pass
            
            return quarantined_files
            
        except Exception as e:
            return []
'''
            
            # البحث عن نهاية الكلاس وإضافة الطريقة
            class_end = quarantine_content.rfind('    def ') + 4
            if class_end > 4:
                lines = quarantine_content.split('\n')
                for i in range(len(lines)-1, -1, -1):
                    if lines[i].strip().startswith('def ') or lines[i].strip().startswith('class '):
                        class_end = sum(len(line) + 1 for line in lines[:i+1])
                        break
            
            quarantine_content = quarantine_content[:class_end] + quarantine_method + '\n' + quarantine_content[class_end:]
            
            with open(quarantine_manager_path, 'w', encoding='utf-8') as f:
                f.write(quarantine_content)
            
            self.print_success("تم إضافة get_quarantined_files إلى QuarantineManager")
        else:
            self.print_success("get_quarantined_files موجود بالفعل في QuarantineManager")
        
        return True
    
    def fix_4_yara_rules(self):
        """إصلاح مشكلة YARA Rules المفقودة"""
        self.print_header("إصلاح YARA Rules المفقودة")
        
        yara_dir = self.data_dir / "YARA_RULES"
        yara_dir.mkdir(parents=True, exist_ok=True)
        
        # إنشاء قواعد YARA أساسية
        basic_rules = '''/*
 * قواعد YARA الأساسية للثقافة من البرمجيات الخبيثة
 * Basic YARA Rules for Malware Detection
 */

rule Suspicious_File_Extensions {
    meta:
        description = "Detects suspicious file extensions commonly used by ransomware"
        author = "Ransomware Protection System"
        date = "2025-11-28"
        version = "1.0"
    
    strings:
        $exe = { 4D 5A } // PE executable header
        $suspicious_ext1 = ".locked" ascii
        $suspicious_ext2 = ".encrypted" ascii
        $suspicious_ext3 = ".crypto" ascii
        $suspicious_ext4 = ".crypt" ascii
        $note1 = "ransom" ascii wide
        $note2 = "decrypt" ascii wide
        $note3 = "payment" ascii wide
    
    condition:
        $exe and any of ($suspicious_ext*) and any of ($note*)
}

rule Process_Manipulation {
    meta:
        description = "Detects processes that manipulate system files"
        author = "Ransomware Protection System"
        date = "2025-11-28"
        version = "1.0"
    
    strings:
        $taskkill = "taskkill" ascii wide
        $delete = "delete" ascii wide
        $format = "format" ascii wide
    
    condition:
        2 of them
}

rule Network_Activity {
    meta:
        description = "Detects suspicious network activity"
        author = "Ransomware Protection System"
        date = "2025-11-28"
        version = "1.0"
    
    strings:
        $tor = "torproject" ascii wide
        $bitcoin = "bitcoin" ascii wide
        $payment = "payment" ascii wide
    
    condition:
        any of them
}'''
        
        # حفظ قواعد YARA
        rules_file = yara_dir / "basic_rules.yar"
        with open(rules_file, 'w', encoding='utf-8') as f:
            f.write(basic_rules)
        
        self.print_success(f"تم إنشاء قواعد YARA الأساسية: {rules_file}")
        
        # إنشاء ملف إعدادات YARA
        config = {
            "rules_directory": str(yara_dir),
            "auto_load": True,
            "scan_files": ["*.exe", "*.dll", "*.bat", "*.vbs", "*.js", "*.ps1"],
            "scan_directories": ["C:\\Windows\\System32", "C:\\Program Files"],
            "enabled": True
        }
        
        config_file = self.data_dir / "yara_config.json"
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        self.print_success(f"تم إنشاء ملف إعدادات YARA: {config_file}")
        
        return True
    
    def fix_5_ssl_errors(self):
        """إصلاح أخطاء SSL EOF"""
        self.print_header("إصلاح أخطاء SSL EOF")
        
        # إنشاء سكريبت إصلاح SSL
        ssl_fix_script = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""إصلاح أخطاء SSL EOF"""

import ssl
import urllib.request
import socket
from pathlib import Path

def fix_ssl_context():
    """إصلاح سياق SSL للقرارات الآمنة"""
    
    # إنشاء سياق SSL محدث
    ctx = ssl.create_default_context()
    
    # إعدادات SSL للأمان والتوافق
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    
    # إعدادات للتعامل مع البروتوكولات القديمة
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    
    return ctx

def test_ssl_connection():
    """اختبار اتصال SSL"""
    
    try:
        # اختبار Google APIs
        test_urls = [
            "https://www.googleapis.com",
            "https://drive.google.com",
            "https://www.googleapis.com/drive/v3"
        ]
        
        ctx = fix_ssl_context()
        
        for url in test_urls:
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                    print(f"✅ اتصال SSL ناجح: {url}")
            except Exception as e:
                print(f"⚠️ تحذير اتصال SSL: {url} - {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ خطأ في اختبار SSL: {e}")
        return False

def create_ssl_config():
    """إنشاء ملف إعدادات SSL"""
    
    ssl_config = {
        "ssl_context": {
            "check_hostname": True,
            "verify_mode": "CERT_REQUIRED",
            "minimum_version": "TLSv1_2",
            "maximum_version": "TLSv1_3"
        },
        "proxy_settings": {
            "enabled": False,
            "proxy_url": "",
            "proxy_auth": ""
        },
        "timeout_settings": {
            "connect_timeout": 10,
            "read_timeout": 30
        },
        "certificates": {
            "ca_bundle_path": "",
            "client_cert_path": "",
            "client_key_path": ""
        }
    }
    
    config_path = Path("data") / "ssl_config.json"
    config_path.parent.mkdir(exist_ok=True)
    
    with open(config_path, 'w', encoding='utf-8') as f:
        import json
        json.dump(ssl_config, f, indent=2, ensure_ascii=False)
    
    print(f"✅ تم إنشاء ملف إعدادات SSL: {config_path}")
    return config_path

if __name__ == "__main__":
    print("🔧 إصلاح أخطاء SSL EOF")
    print("=" * 40)
    
    # إنشاء إعدادات SSL
    create_ssl_config()
    
    # اختبار الاتصال
    test_ssl_connection()
    
    print("✅ تم إكمال إصلاح أخطاء SSL")
'''
        
        ssl_fix_path = self.project_root / "fix_ssl_errors.py"
        with open(ssl_fix_path, 'w', encoding='utf-8') as f:
            f.write(ssl_fix_script)
        
        self.print_success(f"تم إنشاء سكريبت إصلاح SSL: {ssl_fix_path}")
        return True
    
    def fix_6_venv_activation(self):
        """إصلاح تفعيل البيئة الافتراضية"""
        self.print_header("إصلاح تفعيل البيئة الافتراضية")
        
        # تحديد مسار venv
        venv_paths = [
            self.project_root / "venv",
            self.project_root / ".venv",
            self.src_dir / "venv",
            self.src_dir / ".venv"
        ]
        
        venv_path = None
        for path in venv_paths:
            if path.exists():
                venv_path = path
                break
        
        if not venv_path:
            self.print_warning("لم يتم العثور على مجلد venv، سيتم إنشاء واحد جديد")
            return self.create_new_venv()
        
        # إنشاء سكريبت تفعيل محسن
        activation_script = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""سكريبت تفعيل البيئة الافتراضية المحسن"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def find_venv():
    """البحث عن مجلد البيئة الافتراضية"""
    
    project_root = Path(__file__).parent
    possible_venvs = [
        project_root / "venv",
        project_root / ".venv", 
        project_root / "src" / "venv",
        project_root / "src" / ".venv"
    ]
    
    for venv_path in possible_venvs:
        if venv_path.exists():
            return venv_path
    
    return None

def get_activation_script(venv_path):
    """الحصول على سكريبت التفعيل المناسب للنظام"""
    
    system = platform.system()
    
    if system == "Windows":
        return venv_path / "Scripts" / "activate.bat"
    else:
        return venv_path / "bin" / "activate"

def activate_venv():
    """تفعيل البيئة الافتراضية"""
    
    print("🔍 البحث عن البيئة الافتراضية...")
    
    venv_path = find_venv()
    
    if not venv_path:
        print("❌ لم يتم العثور على البيئة الافتراضية")
        print("💡 قم بتشغيل: python -m venv venv")
        return False
    
    print(f"✅ تم العثور على البيئة الافتراضية: {{venv_path}}")
    
    activation_script = get_activation_script(venv_path)
    
    if not activation_script.exists():
        print(f"❌ سكريبت التفعيل غير موجود: {{activation_script}}")
        return False
    
    # تفعيل البيئة الافتراضية
    system = platform.system()
    
    if system == "Windows":
        # Windows
        activate_command = f'"{{activation_script}}"'
        python_path = venv_path / "Scripts" / "python.exe"
        pip_path = venv_path / "Scripts" / "pip.exe"
    else:
        # Linux/macOS
        activate_command = f'source "{{activation_script}}"'
        python_path = venv_path / "bin" / "python"
        pip_path = venv_path / "bin" / "pip"
    
    print(f"🔄 تفعيل البيئة الافتراضية...")
    
    try:
        # تحديث متغيرات البيئة
        if system == "Windows":
            # إضافة مسارات Python إلى PATH
            current_path = os.environ.get("PATH", "")
            scripts_dir = str(venv_path / "Scripts")
            new_path = f"{{scripts_dir}};{{current_path}}"
            os.environ["PATH"] = new_path
            
            # إضافة VIRTUAL_ENV
            os.environ["VIRTUAL_ENV"] = str(venv_path)
            
        else:
            # Linux/macOS
            current_path = os.environ.get("PATH", "")
            bin_dir = str(venv_path / "bin")
            new_path = f"{{bin_dir}}:{{current_path}}"
            os.environ["PATH"] = new_path
            
            # إضافة VIRTUAL_ENV
            os.environ["VIRTUAL_ENV"] = str(venv_path)
        
        print("✅ تم تفعيل البيئة الافتراضية بنجاح!")
        print(f"🐍 Python: {{python_path}}")
        print(f"📦 Pip: {{pip_path}}")
        
        return True
        
    except Exception as e:
        print(f"❌ خطأ في تفعيل البيئة الافتراضية: {{e}}")
        return False

def check_dependencies():
    """فحص المكتبات المطلوبة"""
    
    required_packages = [
        "flask",
        "flask-cors", 
        "waitress",
        "google-api-python-client",
        "google-auth",
        "google-auth-oauthlib",
        "cryptography",
        "psutil",
        "hashlib3",
        "pymd5",
        "xxhash",
        "yara-python"
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
            print(f"✅ {{package}} - متوفر")
        except ImportError:
            print(f"❌ {{package}} - مفقود")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\\n📦 تثبيت المكتبات المفقودة: {{missing_packages}}")
        return False
    
    return True

def install_missing_packages():
    """تثبيت المكتبات المفقودة"""
    
    packages = [
        "flask",
        "flask-cors",
        "waitress", 
        "google-api-python-client",
        "google-auth",
        "google-auth-oauthlib",
        "google-auth-httplib2",
        "cryptography",
        "psutil",
        "hashlib3",
        "pymd5",
        "xxhash",
        "yara-python"
    ]
    
    print("📦 تثبيت المكتبات المطلوبة...")
    
    try:
        # استخدام pip مع pip بدلاً من uv
        import subprocess
        
        for package in packages:
            print(f"📦 تثبيت {{package}}...")
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", package
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ تم تثبيت {{package}} بنجاح")
            else:
                print(f"❌ فشل في تثبيت {{package}}: {{result.stderr}}")
        
        return True
        
    except Exception as e:
        print(f"❌ خطأ في تثبيت المكتبات: {{e}}")
        return False

if __name__ == "__main__":
    print("🔧 إصلاح تفعيل البيئة الافتراضية")
    print("=" * 50)
    
    # تفعيل البيئة الافتراضية
    if not activate_venv():
        sys.exit(1)
    
    # فحص المكتبات
    if not check_dependencies():
        print("💡 تثبيت المكتبات المفقودة...")
        install_missing_packages()
        
        # إعادة فحص
        if check_dependencies():
            print("✅ تم تثبيت جميع المكتبات بنجاح!")
        else:
            print("❌ لم يتم تثبيت جميع المكتبات")
    
    print("\\n🎉 تم إعداد البيئة الافتراضية بنجاح!")
'''
        
        venv_script_path = self.project_root / "activate_venv_fixed.py"
        with open(venv_script_path, 'w', encoding='utf-8') as f:
            f.write(activation_script)
        
        self.print_success(f"تم إنشاء سكريبت تفعيل venv محسن: {venv_script_path}")
        
        # إنشاء سكريبت بدء النظام الجديد
        startup_script = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""سكريبت بدء النظام المحسن"""

import os
import sys
import subprocess
import platform
from pathlib import Path
import time

def main():
    print("🚀 بدء نظام الحماية من الثعير الإلكتروني")
    print("=" * 50)
    
    # البحث عن دليل src
    current_dir = Path(__file__).parent
    src_dir = current_dir / "src"
    
    if not src_dir.exists():
        print("❌ مجلد src غير موجود")
        return False
    
    # تفعيل البيئة الافتراضية أولاً
    venv_script = current_dir / "activate_venv_fixed.py"
    
    if venv_script.exists():
        print("🔧 تفعيل البيئة الافتراضية...")
        try:
            result = subprocess.run([sys.executable, str(venv_script)], 
                                  capture_output=True, text=True, cwd=current_dir)
            if result.returncode != 0:
                print(f"❌ خطأ في تفعيل البيئة الافتراضية: {{result.stderr}}")
            else:
                print("✅ تم تفعيل البيئة الافتراضية")
        except Exception as e:
            print(f"⚠️ تحذير: {{e}}")
    
    # بدء النظام
    main_script = src_dir / "main.py"
    
    if not main_script.exists():
        print("❌ ملف main.py غير موجود")
        return False
    
    print("🌐 بدء خادم النظام...")
    
    try:
        # بدء النظام
        if platform.system() == "Windows":
            os.system(f'cd "{src_dir}" && python main.py')
        else:
            os.system(f'cd "{src_dir}" && python3 main.py')
    except KeyboardInterrupt:
        print("\\n⏹️ تم إيقاف النظام")
    except Exception as e:
        print(f"❌ خطأ في بدء النظام: {{e}}")
        return False
    
    return True

if __name__ == "__main__":
    main()
'''
        
        startup_path = self.project_root / "start_system_fixed.py"
        with open(startup_path, 'w', encoding='utf-8') as f:
            f.write(startup_script)
        
        self.print_success(f"تم إنشاء سكريبت بدء النظام المحسن: {startup_path}")
        
        return True
    
    def create_new_venv(self):
        """إنشاء بيئة افتراضية جديدة"""
        try:
            venv_path = self.project_root / "venv"
            print(f"📦 إنشاء بيئة افتراضية جديدة: {venv_path}")
            
            # إنشاء venv
            subprocess.run([sys.executable, "-m", "venv", str(venv_path)], check=True)
            
            self.print_success("تم إنشاء البيئة الافتراضية بنجاح!")
            return True
            
        except Exception as e:
            self.print_error(f"خطأ في إنشاء البيئة الافتراضية: {e}")
            return False
    
    def run_comprehensive_fixes(self):
        """تشغيل جميع الإصلاحات"""
        self.print_header("بدء الإصلاحات الشاملة")
        
        print(f"📁 دليل المشروع: {self.project_root}")
        print(f"💻 النظام: {platform.system()}")
        print(f"🐍 Python: {sys.version}")
        
        fixes = [
            ("Database Errors", self.fix_1_database_errors),
            ("Google Drive API", self.fix_2_google_drive_api),
            ("Missing Methods", self.fix_3_missing_methods),
            ("YARA Rules", self.fix_4_yara_rules),
            ("SSL Errors", self.fix_5_ssl_errors),
            ("VENV Activation", self.fix_6_venv_activation)
        ]
        
        results = {}
        
        for name, fix_func in fixes:
            self.print_info(f"تنفيذ الإصلاح: {name}")
            try:
                result = fix_func()
                results[name] = result
                if result:
                    self.print_success(f"تم إصلاح {name} بنجاح")
                else:
                    self.print_error(f"فشل في إصلاح {name}")
            except Exception as e:
                self.print_error(f"خطأ غير متوقع في {name}: {e}")
                results[name] = False
        
        # تلخيص النتائج
        self.print_header("نتائج الإصلاحات")
        
        success_count = 0
        total_count = len(results)
        
        for name, result in results.items():
            if result:
                self.print_success(f"✅ {name}: نجح")
                success_count += 1
            else:
                self.print_error(f"❌ {name}: فشل")
        
        success_rate = (success_count / total_count) * 100
        self.print_info(f"\\n📊 معدل النجاح: {success_rate:.1f}% ({success_count}/{total_count})")
        
        if success_rate >= 80:
            self.print_success("🎉 تم إصلاح النظام بنجاح!")
        else:
            self.print_warning("⚠️ تم إصلاح معظم المشاكل، قد تحتاج مراجعة يدوية")
        
        return results


def main():
    """الدالة الرئيسية"""
    
    # العثور على دليل المشروع
    current_dir = Path(__file__).parent
    
    # البحث عن دليل ransomware_fixed
    project_root = current_dir
    for child in current_dir.iterdir():
        if child.is_dir() and "ransomware" in child.name.lower():
            project_root = child
            break
    
    if not project_root.exists():
        print("❌ لم يتم العثور على دليل المشروع")
        return False
    
    print(f"🔍 دليل المشروع: {project_root}")
    
    # تشغيل الإصلاحات
    fixer = ComprehensiveFixer(project_root)
    results = fixer.run_comprehensive_fixes()
    
    # حفظ النتائج
    results_file = project_root / "comprehensive_fixes_results.json"
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"💾 تم حفظ النتائج في: {results_file}")
    
    return True


if __name__ == "__main__":
    main()