import streamlit as st
import pyAesCrypt
import os

# Define buffer size
buffersize = 64 * 1024  # 64kb size of file

# Streamlit interface
st.title("File Encryption and Decryption")

# Upload file
uploaded_file = st.file_uploader("Choose a file")

# Get password from user
password = st.text_input("Enter password to encrypt or decrypt your file", type="password")

# Get option to encrypt or decrypt
operation = st.selectbox("Choose operation", ("Encrypt", "Decrypt"))

# Initialize variables for filenames
input_filename = None
output_filename = None

# Process file
if uploaded_file and password:
    file_details = {"filename": uploaded_file.name, "filetype": uploaded_file.type}
    st.write(file_details)

    # Save uploaded file
    input_filename = uploaded_file.name
    with open(input_filename, "wb") as f:
        f.write(uploaded_file.getbuffer())

    if operation == "Encrypt":
        output_filename = input_filename + ".vic"
        try:
            # Encrypt file
            pyAesCrypt.encryptFile(input_filename, output_filename, password, buffersize)
            st.success("File encrypted successfully")

            # Provide download link
            with open(output_filename, "rb") as f:
                st.download_button(label="Download Encrypted File", data=f, file_name=output_filename, mime="application/octet-stream")
        except Exception as e:
            st.error(f"Error encrypting file: {e}")

    elif operation == "Decrypt":
        if input_filename.endswith(".vic"):
            output_filename = input_filename.replace(".vic", "")
            try:
                # Decrypt file
                pyAesCrypt.decryptFile(input_filename, output_filename, password, buffersize)
                st.success("File decrypted successfully")

                # Provide download link
                with open(output_filename, "rb") as f:
                    st.download_button(label="Download Decrypted File", data=f, file_name=output_filename, mime="application/octet-stream")
            except Exception as e:
                st.error(f"Error decrypting file: {e}")
        else:
            st.error("Please upload a valid encrypted (.vic) file for decryption.")

    # Cleanup
    if input_filename and os.path.exists(input_filename):
        os.remove(input_filename)
    if output_filename and os.path.exists(output_filename):
        os.remove(output_filename)
