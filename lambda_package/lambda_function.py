import json
import urllib.request
import jwt
from jwt.algorithms import RSAAlgorithm

USER_POOL_ID = 'eu-west-1_n9ubrt0le'
REGION = 'eu-west-1'
APP_CLIENT_ID = '1eigb99bdtp6n8dk5a8el3ov4f'

# Construct JWKs URL
JWK_URL = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json"

# Load and parse public keys
with urllib.request.urlopen(JWK_URL) as response:
    keys = json.loads(response.read().decode("utf-8"))["keys"]

def lambda_handler(event, context):
    try:
        # Get token from the Authorization header
        auth_header = event["headers"].get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return { "statusCode": 401, "body": json.dumps({"message": "Missing Bearer token"}) }

        token = auth_header.split(" ")[1]

        # Decode the JWT header to get the kid
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header["kid"]

        # Find the matching public key
        key = next((k for k in keys if k["kid"] == kid), None)
        if key is None:
            return { "statusCode": 401, "body": json.dumps({"message": "Invalid key ID"}) }

        # Build the public RSA key
        public_key = RSAAlgorithm.from_jwk(json.dumps(key))

        # Decode and verify the token
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=APP_CLIENT_ID,
            issuer=f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"
        )

        #Token is valid!
        return {
            "statusCode": 200,
            "body": json.dumps({"message": "Token is valid!", "claims": decoded})
        }

    except jwt.ExpiredSignatureError:
        return { "statusCode": 401, "body": json.dumps({"message": "Token expired"}) }

    except jwt.InvalidTokenError as e:
        return { "statusCode": 401, "body": json.dumps({"message": f"Invalid token: {str(e)}"}) }

    except Exception as e:
        return { "statusCode": 500, "body": json.dumps({"message": f"Internal error: {str(e)}"}) }

