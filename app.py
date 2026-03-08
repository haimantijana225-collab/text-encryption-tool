import streamlit as st
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import secrets
import string

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="Text Encryption Tool",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 Multi-Algorithm Text Encryption System")
st.markdown("Secure text using AES, DES, and RSA encryption algorithms.")
st.markdown("---")

# ---------------- KEY GENERATOR ----------------
def generate_key(length):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

# ---------------- AES FUNCTIONS ----------------
def encrypt_aes(text, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())

    encrypted = cipher.nonce + tag + ciphertext
    return base64.b64encode(encrypted).decode()

def decrypt_aes(encrypted_text, key):
    data = base64.b64decode(encrypted_text)

    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)

    return decrypted.decode()

# ---------------- DES FUNCTIONS ----------------
def encrypt_des(text, key):
    cipher = DES.new(key, DES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())

    encrypted = cipher.nonce + tag + ciphertext
    return base64.b64encode(encrypted).decode()

def decrypt_des(encrypted_text, key):
    data = base64.b64decode(encrypted_text)

    nonce = data[:8]
    tag = data[8:16]
    ciphertext = data[16:]

    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)

    return decrypted.decode()

# ---------------- RSA KEYS ----------------
if "rsa_key" not in st.session_state:
    st.session_state.rsa_key = RSA.generate(2048)

public_key = st.session_state.rsa_key.publickey()
private_key = st.session_state.rsa_key

# ---------------- RSA FUNCTIONS ----------------
def encrypt_rsa(text):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(text.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_rsa(encrypted_text):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
    return decrypted.decode()

# ---------------- UI ----------------
algorithm = st.selectbox(
    "Select Encryption Algorithm",
    ["AES", "DES", "RSA"]
)

st.markdown("### Enter Text")
text = st.text_area("", height=120)

st.markdown("---")

# ---------------- AES UI ----------------
if algorithm == "AES":

    st.subheader("AES Encryption (128-bit)")

    col1, col2 = st.columns([3,1])

    with col1:
        key = st.text_input("Enter 16-character key", type="password")

    with col2:
        if st.button("Generate AES Key"):
            generated = generate_key(16)
            st.success(generated)
            key = generated

    col3, col4 = st.columns(2)

    with col3:
        if st.button("Encrypt AES"):
            if len(key) != 16:
                st.error("Key must be exactly 16 characters!")
            else:
                result = encrypt_aes(text, key.encode())
                st.success("Encrypted Text:")
                st.code(result)

    with col4:
        if st.button("Decrypt AES"):
            if len(key) != 16:
                st.error("Key must be exactly 16 characters!")
            else:
                try:
                    result = decrypt_aes(text, key.encode())
                    st.success("Decrypted Text:")
                    st.code(result)
                except:
                    st.error("Invalid key or encrypted text!")

# ---------------- DES UI ----------------
elif algorithm == "DES":

    st.subheader("DES Encryption")

    col1, col2 = st.columns([3,1])

    with col1:
        key = st.text_input("Enter 8-character key", type="password")

    with col2:
        if st.button("Generate DES Key"):
            generated = generate_key(8)
            st.success(generated)
            key = generated

    col3, col4 = st.columns(2)

    with col3:
        if st.button("Encrypt DES"):
            if len(key) != 8:
                st.error("Key must be exactly 8 characters!")
            else:
                result = encrypt_des(text, key.encode())
                st.success("Encrypted Text:")
                st.code(result)

    with col4:
        if st.button("Decrypt DES"):
            if len(key) != 8:
                st.error("Key must be exactly 8 characters!")
            else:
                try:
                    result = decrypt_des(text, key.encode())
                    st.success("Decrypted Text:")
                    st.code(result)
                except:
                    st.error("Invalid key or encrypted text!")

# ---------------- RSA UI ----------------
elif algorithm == "RSA":

    st.subheader("RSA Public-Key Encryption (2048-bit)")
    st.info("Public Key is used for encryption and Private Key for decryption.")

    st.text_area("Public Key", public_key.export_key().decode(), height=150)
    st.text_area("Private Key", private_key.export_key().decode(), height=150)

    col5, col6 = st.columns(2)

    with col5:
        if st.button("Encrypt RSA"):
            result = encrypt_rsa(text)
            st.success("Encrypted Text:")
            st.code(result)

    with col6:
        if st.button("Decrypt RSA"):
            try:
                result = decrypt_rsa(text)
                st.success("Decrypted Text:")
                st.code(result)
            except:
                st.error("Invalid encrypted text!")

# ---------------- FOOTER ----------------
st.markdown("---")
st.markdown("🔐 Developed as a Cybersecurity Internship Project | 2026")
