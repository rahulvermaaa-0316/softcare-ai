import os
import requests
import json
import sys
from dotenv import load_dotenv

sys.stdout.reconfigure(encoding='utf-8')
load_dotenv(override=True)

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

if not SENDGRID_API_KEY:
    print("API Key missing")
    exit(1)

headers = {
    "Authorization": f"Bearer {SENDGRID_API_KEY}",
    "Content-Type": "application/json"
}

print(f"Checking verified senders for API Key: {SENDGRID_API_KEY[:5]}...")

try:
    response = requests.get("https://api.sendgrid.com/v3/senders", headers=headers)
    if response.status_code == 200:
        senders = response.json()
        if not senders:
            print("[INFO] No sender identities found.")
            print("1. Did you verify the email link?")
            print("2. Are you sure this API Key matches the account you verified?")
        else:
            print("[OK] Found Senders:")
            for s in senders:
                status = "VERIFIED" if s.get('verified', {}).get('status') else "UNVERIFIED"
                print(f" - {s.get('from', {}).get('email')} [{status}] (ID: {s.get('id')})")
    else:
        print(f"[ERROR] Error fetching senders: {response.status_code}")
        print(response.text)

except Exception as e:
    print(f"Error: {e}")
