import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- App Setup ---
st.set_page_config(page_title="🔐 Secure Encryption", layout="centered")

# --- Generate a Key for Encryption (demo only) ---
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
cipher = Fernet(st.session_state.fernet_key)

# --- In-Memory Data Store ---
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {"encrypted_text": {"encrypted_text": ..., "passkey": ...}}

# --- Track Failed Attempts ---
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# --- Hashing Function ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# --- Encrypt Function ---
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# --- Decrypt Function ---
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    data = st.session_state.stored_data.get(encrypted_text)
    if data and data["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# --- Login Reset ---
def reauthorize(login_pass):
    if login_pass == "admin123":  # Replace with env variable or secure store in production
        st.session_state.failed_attempts = 0
        st.success("✅ Reauthorized! You can now try again.")
        st.info("Go to the **Retrieve Data** page to retry.")
    else:
        st.error("❌ Incorrect master password!")

# --- UI Pages ---
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("📁 Menu", menu)

# Home Page
if choice == "Home":
    st.header("🏠 Welcome")
    st.write("""
    This application allows you to:
    - Securely store sensitive data using a unique passkey
    - Retrieve and decrypt the data by providing the correct passkey
    - After 3 failed attempts, login is required
    """)

# Store Data
elif choice == "Store Data":
    st.header("📂 Store Data Securely")
    user_data = st.text_area("Enter your secret text:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)

            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }

            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted, language='text')
        else:
            st.warning("⚠️ Both fields are required.")

# Retrieve Data
elif choice == "Retrieve Data":
    st.header("🔍 Retrieve Your Data")

    if st.session_state.failed_attempts >= 3:
        st.warning("🚫 Too many failed attempts! Please log in again.")
        st.info("Navigate to the **Login** tab.")
    else:
        encrypted_text = st.text_area("Enter the encrypted text:")
        passkey = st.text_input("Enter the passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                decrypted = decrypt_data(encrypted_text, passkey)
                if decrypted:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted, language="text")
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
            else:
                st.warning("⚠️ Both fields are required.")

# Login Page
elif choice == "Login":
    st.header("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        reauthorize(login_pass)
