import jwt
import requests

# Load JWT from file
with open('web/.well-known/ato/ato.jwt', 'r') as file:
    jwt_token = file.read().strip()

# Decode JWT header to extract the JWK URL (jku)
header = jwt.get_unverified_header(jwt_token)
jku_url = header['jku']

# Fetch the JWK from the specified URL
jwk_response = requests.get(jku_url)
jwk = jwk_response.json()

# Define the algorithm to use based on the JWK 'alg' field
algorithm = jwk['alg']

# Try to verify the JWT signature
try:
    # Using RS256 algorithm as indicated by the JWT header
    payload = jwt.decode(jwt_token, jwk, algorithms=[algorithm], options={"verify_aud": False})
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
