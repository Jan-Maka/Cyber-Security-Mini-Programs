from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private.decode(), pem_public.decode()

def save_rsa_key_to_file(path, data):
    with path.open('w') as f:
        f.write(data)

def load_rsa_key_from_file(path):
    with path.open('rb') as f:
        return f.read()

def encrypt_with_rsa(pub_key, data):
    key = RSA.import_key(pub_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted = cipher.encrypt(data)
    return encrypted

def decrypt_with_rsa(priv_key, encrypted_data):
    private_key = RSA.import_key(priv_key)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(encrypted_data)
    return decrypted

def generate_x509_certificate(user_public_key_pem, server_private_key_pem,username):
    user_public_key = serialization.load_pem_public_key(user_public_key_pem)
    server_private_key = serialization.load_pem_private_key(server_private_key_pem, password=None)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "JAN INDUSTRIES")
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now())
        .not_valid_after(datetime.now()+ timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .sign(private_key=server_private_key,algorithm=hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.PEM)

def save_certificate(path, certificate):
    with open(path, "wb") as f:
        f.write(certificate)

def load_certficate(path):
    with path.open('rb') as f:
        return f.read()