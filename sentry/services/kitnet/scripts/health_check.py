#!/usr/bin/env python3
"""
Health check script for KitNET service
"""

import sys
import requests
import os

def main():
    try:
        bridge_url = os.getenv('BRIDGE_URL', 'http://bridge:8001')
        
        # Check if service is responsive
        response = requests.get(f"{bridge_url}/health", timeout=5)
        
        if response.status_code == 200:
            print("KitNET service healthy")
            sys.exit(0)
        else:
            print(f"KitNET service unhealthy: {response.status_code}")
            sys.exit(1)
            
    except Exception as e:
        print(f"KitNET service check failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()