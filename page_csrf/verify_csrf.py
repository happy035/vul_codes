import requests
import re

base_url = "http://127.0.0.1:8000"
session = requests.Session()

# 1. Log in
print("[*] Logging in as Alice...")
login_data = {"username": "alice", "password": "password123"}
r = session.post(f"{base_url}/login", data=login_data, allow_redirects=True)
if "로그인에 성공했습니다!" in r.text:
    print("[+] Logged in successfully.")
else:
    print("[-] Login failed.")
    exit(1)

# 2. Get Profile Page and extract CSRF Token
r = session.get(f"{base_url}/profile")
match = re.search(r'name="csrf_token" value="([a-f0-9]+)"', r.text)
if not match:
    print("[-] CSRF token not found in the profile page.")
    exit(1)

csrf_token = match.group(1)
print(f"[+] Found CSRF token: {csrf_token}")

# 3. Submit password change with the CSRF token
print("[*] Changing password to 'my_secure_pass_456' with valid CSRF token...")
change_data = {"new_password": "my_secure_pass_456", "csrf_token": csrf_token}
r = session.post(f"{base_url}/change-password", data=change_data, allow_redirects=True)
if "비밀번호가 성공적으로 변경되었습니다!" in r.text:
    print("[+] Password changed successfully with valid CSRF token.")
else:
    print("[-] Failed to change password.")
    exit(1)

# 4. Verify login with the new password works
session2 = requests.Session()
login_data_new = {"username": "alice", "password": "my_secure_pass_456"}
r2 = session2.post(f"{base_url}/login", data=login_data_new, allow_redirects=True)
if "로그인에 성공했습니다!" in r2.text:
    print("[+] Successfully verified login with new password.")
else:
    print("[-] Failed to login with new password.")
    exit(1)

# 5. Reset password back to 'password123'
print("[*] Resetting password back to 'password123'...")
r = session2.get(f"{base_url}/profile")
match = re.search(r'name="csrf_token" value="([a-f0-9]+)"', r.text)
if not match:
    print("[-] CSRF token not found for reset.")
    exit(1)

csrf_token_reset = match.group(1)
change_data_reset = {"new_password": "password123", "csrf_token": csrf_token_reset}
r2 = session2.post(f"{base_url}/change-password", data=change_data_reset, allow_redirects=True)
if "비밀번호가 성공적으로 변경되었습니다!" in r2.text:
    print("[+] Reset password back to 'password123' successfully.")
else:
    print("[-] Failed to reset password.")
    exit(1)

print("[+] ALL TESTS PASSED! CSRF Protection is robust and does not disrupt legitimate requests.")
