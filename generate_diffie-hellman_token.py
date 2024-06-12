from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate Diffie-Hellman parameters
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# Generate a private key for the backend
private_key = parameters.generate_private_key()

# Generate the public key to share with users
public_key = private_key.public_key()

# Serialize the private key to PEM format
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize the public key to PEM format
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save the private and public key to files
with open("backend_private_key.pem", "wb") as f:
    f.write(private_key_pem)

with open("backend_public_key.pem", "wb") as f:
    f.write(public_key_pem)

print("Backend Private Key PEM:")
print(private_key_pem.decode())

print("Backend Public Key PEM:")
print(public_key_pem.decode())
