import os
import streamlit as st
import pyAesCrypt
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Define buffer size
buffersize = 64 * 1024  # 64kb size of file

# Load backend private key
with open("backend_private_key.pem", "rb") as f:
    backend_private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())

# Load backend public key
with open("backend_public_key.pem", "rb") as f:
    backend_public_key = load_pem_public_key(f.read(), backend=default_backend())

# Streamlit interface
st.title("File Encryption and Decryption")

# Upload file
uploaded_file = st.file_uploader("Choose a file")

# Get user password input
password = st.text_input("Enter your password", type="password")

# Get option to encrypt or decrypt
operation = st.selectbox("Choose operation", ("Encrypt", "Decrypt"))

# Process file
if uploaded_file and password:
    file_details = {"filename": uploaded_file.name, "filetype": uploaded_file.type}
    st.write(file_details)

    # Save uploaded file
    input_filename = uploaded_file.name
    with open(input_filename, "wb") as f:
        f.write(uploaded_file.getbuffer())

    # Derive key using Diffie-Hellman and the user's password
    shared_key = backend_private_key.exchange(backend_public_key)  # Key exchange with constant backend key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=password.encode(),  # Use the user's password as the salt
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    
    if operation == "Encrypt":
        output_filename = input_filename + ".enc"
        try:
            # Encrypt file
            pyAesCrypt.encryptFile(input_filename, output_filename, derived_key.hex(), buffersize)
            st.success("File encrypted successfully")

            # Provide download link
            with open(output_filename, "rb") as f:
                st.download_button(label="Download Encrypted File", data=f, file_name=output_filename, mime="application/octet-stream")
        except Exception as e:
            st.error(f"Error encrypting file: {e}")

    elif operation == "Decrypt":
        if input_filename.endswith(".enc"):
            output_filename = input_filename.replace(".enc", "")
            try:
                # Decrypt file
                pyAesCrypt.decryptFile(input_filename, output_filename, derived_key.hex(), buffersize)
                st.success("File decrypted successfully")

                # Provide download link
                with open(output_filename, "rb") as f:
                    st.download_button(label="Download Decrypted File", data=f, file_name=output_filename, mime="application/octet-stream")
            except Exception as e:
                st.error(f"Error decrypting file: {e}")
        else:
            st.error("Please upload a valid encrypted (.enc) file for decryption.")

    # Cleanup
    if input_filename and os.path.exists(input_filename):
        os.remove(input_filename)
    if output_filename and os.path.exists(output_filename):
        os.remove(output_filename)
else:
    st.warning("Please upload a file and enter a password.")
