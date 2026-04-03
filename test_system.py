#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اختبار شامل للنظام - System Comprehensive Test
Ransomware Protection System - Full Functionality Test
"""

import requests
import json
import time
import sys
from datetime import datetime

class SystemTester:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.api_base = f"{base_url}/api"
        self.test_results = []
    
    def log_test(self, test_name, success, details="", response_time=0):
        """تسجيل نتائج الاختبار"""
        result = {
            "test": test_name,
            "success": success,
            "details": details,
            "response_time_ms": round(response_time * 1000, 2),
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} | {test_name} | {details} | {response_time:.3f}s")
    
    def test_health_api(self):
        """اختبار Health API"""
        try:
            start_time = time.time()
            response = requests.get(f"{self.api_base}/health", timeout=5)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                expected_keys = ['anomaly', 'ml', 'paused', 'quarantine', 'running', 'yara']
                if all(key in data for key in expected_keys):
                    self.log_test("Health API", True, f"Status: {data}", response_time)
                else:
                    self.log_test("Health API", False, "Missing expected fields", response_time)
            else:
                self.log_test("Health API", False, f"HTTP {response.status_code}", response_time)
        except Exception as e:
            self.log_test("Health API", False, str(e))
    
    def test_stats_api(self):
        """اختبار Stats API"""
        try:
            start_time = time.time()
            response = requests.get(f"{self.api_base}/stats", timeout=5)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and 'data' in data:
                    stats = data['data']
                    self.log_test("Stats API", True, f"Scans: {stats.get('total_scans', 0)}, Quarantined: {stats.get('quarantined', 0)}", response_time)
                else:
                    self.log_test("Stats API", False, "Invalid response structure", response_time)
            else:
                self.log_test("Stats API", False, f"HTTP {response.status_code}", response_time)
        except Exception as e:
            self.log_test("Stats API", False, str(e))
    
    def test_quarantine_api(self):
        """اختبار Quarantine API"""
        try:
            start_time = time.time()
            response = requests.get(f"{self.api_base}/quarantine/list", timeout=5)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    count = len(data.get('data', []))
                    self.log_test("Quarantine List API", True, f"Items: {count}", response_time)
                else:
                    self.log_test("Quarantine List API", False, "API returned success=false", response_time)
            else:
                self.log_test("Quarantine List API", False, f"HTTP {response.status_code}", response_time)
        except Exception as e:
            self.log_test("Quarantine List API", False, str(e))
    
    def test_backup_api(self):
        """اختبار Backup API"""
        try:
            start_time = time.time()
            response = requests.get(f"{self.api_base}/backup/status", timeout=5)
            response_time = time.time() - start_time
            
            # Backup قد يكون معطل وهذا طبيعي
            if response.status_code == 200:
                data = response.json()
                self.log_test("Backup Status API", True, f"Response: {data}", response_time)
            else:
                self.log_test("Backup Status API", False, f"HTTP {response.status_code}", response_time)
        except Exception as e:
            self.log_test("Backup Status API", False, str(e))
    
    def test_control_apis(self):
        """اختبار Control APIs (Start/Stop/Pause/Resume)"""
        apis = ['start', 'stop', 'pause', 'resume']
        
        for api in apis:
            try:
                start_time = time.time()
                response = requests.post(f"{self.api_base}/{api}", timeout=10)
                response_time = time.time() - start_time
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        self.log_test(f"Control {api.upper()} API", True, "Success", response_time)
                    else:
                        self.log_test(f"Control {api.upper()} API", False, "API returned success=false", response_time)
                else:
                    self.log_test(f"Control {api.upper()} API", False, f"HTTP {response.status_code}", response_time)
                
                # انتظار قصير بين الطلبات
                time.sleep(1)
                
            except Exception as e:
                self.log_test(f"Control {api.upper()} API", False, str(e))
    
    def test_monitoring_apis(self):
        """اختبار Monitoring APIs"""
        try:
            # اختبار قائمة المسارات المراقبة
            start_time = time.time()
            response = requests.get(f"{self.api_base}/monitoring/list_paths", timeout=5)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    paths_count = len(data.get('data', []))
                    self.log_test("Monitoring List Paths", True, f"Monitored paths: {paths_count}", response_time)
                else:
                    self.log_test("Monitoring List Paths", False, "API returned success=false", response_time)
            else:
                self.log_test("Monitoring List Paths", False, f"HTTP {response.status_code}", response_time)
        except Exception as e:
            self.log_test("Monitoring List Paths", False, str(e))
    
    def test_web_interface(self):
        """اختبار واجهة الويب الأساسية"""
        try:
            start_time = time.time()
            response = requests.get(self.base_url, timeout=5)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                content = response.text.lower()
                if 'ransomware' in content and 'protection' in content:
                    self.log_test("Web Interface", True, "Main page loads correctly", response_time)
                else:
                    self.log_test("Web Interface", False, "Page loaded but content seems incorrect", response_time)
            else:
                self.log_test("Web Interface", False, f"HTTP {response.status_code}", response_time)
        except Exception as e:
            self.log_test("Web Interface", False, str(e))
    
    def run_all_tests(self):
        """تشغيل جميع الاختبارات"""
        print("=" * 80)
        print("🧪 بدء الاختبار الشامل لنظام الحماية من البرمجيات الخبيثة")
        print("   Ransomware Protection System - Comprehensive Testing")
        print("=" * 80)
        print()
        
        # قائمة جميع الاختبارات
        tests = [
            self.test_health_api,
            self.test_stats_api,
            self.test_quarantine_api,
            self.test_backup_api,
            self.test_monitoring_apis,
            self.test_web_interface,
            self.test_control_apis  # يتم تشغيله آخر لأنه يغير حالة النظام
        ]
        
        # تشغيل الاختبارات
        for test in tests:
            try:
                test()
                time.sleep(0.5)  # انتظار قصير بين الاختبارات
            except Exception as e:
                print(f"❌ ERROR in test {test.__name__}: {e}")
        
        # عرض النتائج النهائية
        self.show_summary()
        
        return self.test_results
    
    def show_summary(self):
        """عرض ملخص النتائج"""
        print("\n" + "=" * 80)
        print("📊 ملخص نتائج الاختبار - Test Summary")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r['success'])
        failed_tests = total_tests - passed_tests
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"📈 Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"📊 Success Rate: {success_rate:.1f}%")
        print()
        
        # عرض الاختبارات الفاشلة (إن وجدت)
        if failed_tests > 0:
            print("🔍 Failed Tests:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  ❌ {result['test']}: {result['details']}")
            print()
        
        # تقييم عام
        if success_rate >= 90:
            print("🎉 EXCELLENT! System is working perfectly!")
            overall_status = "EXCELLENT"
        elif success_rate >= 75:
            print("👍 GOOD! System is mostly working with minor issues.")
            overall_status = "GOOD"
        elif success_rate >= 50:
            print("⚠️  MODERATE! Some features working, needs attention.")
            overall_status = "MODERATE"
        else:
            print("🚨 POOR! System has significant issues.")
            overall_status = "POOR"
        
        print(f"🏆 Overall Status: {overall_status}")
        print("=" * 80)
        
        return overall_status

def main():
    """الدالة الرئيسية"""
    print("🔧 Ransomware Protection System - Comprehensive Test")
    print("📅 Test Time:", datetime.now().isoformat())
    print()
    
    # إنشاء مثيل الاختبار
    tester = SystemTester()
    
    # تشغيل جميع الاختبارات
    results = tester.run_all_tests()
    
    # حفظ النتائج في ملف JSON
    with open('test_results.json', 'w', encoding='utf-8') as f:
        json.dump({
            'test_time': datetime.now().isoformat(),
            'total_tests': len(results),
            'passed': sum(1 for r in results if r['success']),
            'failed': sum(1 for r in results if not r['success']),
            'results': results
        }, f, indent=2, ensure_ascii=False)
    
    print("📁 Test results saved to: test_results.json")
    print("🎯 Test completed successfully!")

if __name__ == "__main__":
    main()