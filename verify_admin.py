
import requests

# Base URL
BASE_URL = "http://127.0.0.1:5000"

# Admin credentials
ADMIN_DATA = {"username": "admin", "password": "admin123"}
WRONG_DATA = {"username": "admin", "password": "wrongpassword"}

# Create a session to persist cookies
session = requests.Session()

print("--- Testing Admin Login (Wrong Password) ---")
res = session.post(f"{BASE_URL}/admin/login", data=WRONG_DATA)
# Should stay on login page (check for "Invalid credentials" in text or just 200 OK)
if "Invalid credentials" in res.text:
    print("[OK] Correctly rejected wrong password.")
else:
    print("[FAIL] Failed: Did not show error for wrong password.")

print("\n--- Testing Admin Login (Correct Password) ---")
res = session.post(f"{BASE_URL}/admin/login", data=ADMIN_DATA)
# Should redirect to dashboard (or return dashboard content directly if using redirect following)
if "Admin Panel" in res.text and "Registered Users" in res.text:
    print("[OK] Login successful. Dashboard accessed.")
else:
    print("[FAIL] Failed: Could not access dashboard.")

print("\n--- Testing Admin Dashboard Access ---")
# Using the SAME session which is now logged in
res = session.get(f"{BASE_URL}/admin/dashboard")
if "Registered Users" in res.text:
    print("[OK] Dashboard content visible.")
else:
    print("[FAIL] Failed: Dashboard not visible.")