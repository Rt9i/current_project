#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API Testing Script after system fixes
"""

import requests
import json
import time

def test_api_endpoints():
    """Test all API endpoints"""
    base_url = "http://localhost:5000"
    
    print("🧪 TESTING API ENDPOINTS")
    print("=" * 40)
    print(f"Testing against: {base_url}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    endpoints = [
        ("Health Check", "/api/health", "GET"),
        ("System Stats", "/api/stats", "GET"),
        ("Quarantine List", "/api/quarantine/list", "GET"),
        ("Backup Status", "/api/backup/status", "GET"),
        ("Monitoring Paths", "/api/monitoring/list_paths", "GET"),
        ("Start Protection", "/api/start", "POST"),
        ("Stop Protection", "/api/stop", "POST"),
        ("Pause Protection", "/api/pause", "POST"),
        ("Resume Protection", "/api/resume", "POST"),
    ]
    
    results = []
    
    for name, endpoint, method in endpoints:
        print(f"Testing: {name}")
        try:
            if method == "GET":
                response = requests.get(f"{base_url}{endpoint}", timeout=5)
            else:
                response = requests.post(f"{base_url}{endpoint}", json={}, timeout=5)
            
            print(f"  Status: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    print(f"  Response: {json.dumps(data, indent=2)[:200]}...")
                    results.append((name, True, None))
                except:
                    print(f"  Response: {response.text[:100]}...")
                    results.append((name, True, None))
            elif response.status_code == 404:
                print(f"  ❌ Endpoint not found")
                results.append((name, False, "404 Not Found"))
            elif response.status_code == 500:
                print(f"  ❌ Internal server error")
                results.append((name, False, "500 Internal Error"))
            else:
                print(f"  ⚠️ Unexpected status: {response.status_code}")
                results.append((name, False, f"Status {response.status_code}"))
                
        except requests.exceptions.ConnectionError:
            print(f"  ❌ Cannot connect to server")
            results.append((name, False, "Connection refused"))
        except Exception as e:
            print(f"  ❌ Error: {e}")
            results.append((name, False, str(e)))
        
        print()
    
    # Summary
    print("=" * 40)
    print("📋 API TEST RESULTS")
    print("=" * 40)
    
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    
    for name, success, error in results:
        status = "✅ PASS" if success else "❌ FAIL"
        detail = f"({error})" if error else ""
        print(f"{status:<8} {name} {detail}")
    
    print(f"\n📊 Success Rate: {passed}/{total} ({passed/total*100:.1f}%)")
    
    if passed >= total * 0.8:
        print("\n🎉 APIs ARE WORKING! Most endpoints respond correctly.")
        return True
    else:
        print(f"\n⚠️ APIs NEED ATTENTION: Only {passed}/{total} working.")
        return False

if __name__ == "__main__":
    test_api_endpoints()
