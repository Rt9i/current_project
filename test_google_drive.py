#!/usr/bin/env python3
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
