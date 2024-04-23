from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import jwt
import requests
import json
import base64

# Function to convert JWK to PEM
def jwk_to_pem(jwk_data):
    public_num = rsa.RSAPublicNumbers(
        e=int.from_bytes(base64.urlsafe_b64decode(jwk_data['e'] + '=='), 'big'),
        n=int.from_bytes(base64.urlsafe_b64decode(jwk_data['n'] + '=='), 'big')
    )
    public_key = public_num.public_key(backend=default_backend())
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

# Load JWT from file
with open('web/.well-known/ato/ato.jwt', 'r') as file:
    jwt_token = file.read().strip()

# Decode JWT header to extract the JWK URL (jku)
header = jwt.get_unverified_header(jwt_token)
jku_url = header['jku']

# Fetch the JWK from the specified URL
jwk_response = requests.get(jku_url)
jwk = jwk_response.json()

# Convert JWK to PEM
pem_key = jwk_to_pem(jwk)

# Define the algorithm to use based on the JWK 'alg' field
algorithm = jwk['alg']

# Try to verify the JWT signature using the PEM key
try:
    # Using RS256 algorithm as indicated by the JWT header
    payload = jwt.decode(jwt_token, pem_key, algorithms=[algorithm], options={"verify_aud": False})
    print("JWT is valid and signature has been successfully verified.")
except jwt.ExpiredSignatureError:
    print("::error::JWT has expired.")
    raise
except jwt.InvalidTokenError as e:
    print(f"::error::JWT signature is invalid: {str(e)}")
    raise
except Exception as e:
    print(f"::error::An error occurred: {str(e)}")
    raise
