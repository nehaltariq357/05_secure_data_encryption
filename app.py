import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Fixed encryption key
KEY = b'ZzJZqNU7F7kp3OPWD1qykG2WL3KvJKMoJhnUj1CJe3Y='
cipher = Fernet(KEY)

# Session state setup
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

# Master password
MASTER_PASSWORD = "admin123"

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt function
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt function
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for data_id, item in st.session_state.stored_data.items():
        if item["encrypted_text"] == encrypted_text and item["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# 🎛 Sidebar Menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Logout option
if st.session_state.logged_in:
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.success("👋 Logged out successfully.")

# Home
if choice == "Home":
    st.title("🔐 Secure Data Encryption System")
    st.subheader("🏠 Welcome to Secure Vault")
    st.write("Use this app to securely store and retrieve data using secret passkeys.")

# Store Data
elif choice == "Store Data":
    st.title("Secure Data Encryption System")
    st.subheader("💾 Store Data Securely")
    user_data = st.text_area("Enter your data to encrypt:")
    passkey = st.text_input("Set your secret passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("Your data has been encrypted and saved securely.")
            st.code(encrypted_text, language='text')
        else:
            st.error("Please enter both data and passkey.")

# Retrieve Data
elif choice == "Retrieve Data":
    st.title("Secure Data Encryption System")
    st.subheader("Retrieve Your Data")

    if not st.session_state.logged_in:
        st.warning("Please login first to retrieve your data.")
        st.stop()

    if st.session_state.failed_attempts >= 3:
        st.warning("Too many failed attempts! Please login again.")
        st.session_state.logged_in = False
        st.stop()

    encrypted_text = st.text_area("Paste your encrypted data:")
    passkey = st.text_input("Enter your secret passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            try:
                decrypted = decrypt_data(encrypted_text, passkey)
                if decrypted:
                    st.success("Decrypted Data:")
                    st.code(decrypted)
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"Incorrect passkey. Attempts left: {attempts_left}")
            except Exception as e:
                st.error(f"Error during decryption: {str(e)}")
        else:
            st.error("Please enter both encrypted text and passkey.")

#  Login
elif choice == "Login":
    st.title("Secure Data Encryption System")
    st.subheader(" Login Required")
    master_password = st.text_input("Enter master password to continue:", type="password")

    if st.button("Login"):
        if master_password == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.session_state.logged_in = True
            st.success(" Login successful. You can now retrieve your data.")
        else:
            st.error("Incorrect master password!")
