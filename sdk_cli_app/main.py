import os
import time
import requests
from urllib.parse import urljoin
from dotenv import load_dotenv
import json

load_dotenv()

# Configuration for Keycloak (should match your poc-realm-realm.json and docker-compose.yml)
KEYCLOAK_BASE_URL = os.getenv("KEYCLOAK_CLI_BASE_URL", "http://localhost:8080/") # From host perspective
KEYCLOAK_REALM = os.getenv("KEYCLOAK_CLI_REALM", "poc-realm")
SDK_CLIENT_ID = os.getenv("KEYCLOAK_CLI_CLIENT_ID", "sdk-cli-client") # Client configured for device flow

# API to call (app1's API)
APP1_API_BASE_URL = os.getenv("APP1_API_BASE_URL", "http://localhost:8091/") # From host perspective
API_DATA_ENDPOINT = urljoin(APP1_API_BASE_URL, "api/data")


def run_device_authorization_flow():
    """
    Implements the OAuth 2.0 Device Authorization Grant.
    """
    keycloak_realm_url = urljoin(KEYCLOAK_BASE_URL, f"realms/{KEYCLOAK_REALM}/")
    device_auth_endpoint = urljoin(keycloak_realm_url, "protocol/openid-connect/auth/device")
    token_endpoint = urljoin(keycloak_realm_url, "protocol/openid-connect/token")

    # 1. Device Authorization Request
    device_auth_payload = {
        'client_id': SDK_CLIENT_ID,
        'scope': 'openid email profile roles' # Request scopes needed
    }
    
    print("Requesting device and user codes...")
    try:
        response = requests.post(device_auth_endpoint, data=device_auth_payload, timeout=10)
        response.raise_for_status()
        device_auth_data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error during device authorization request: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response content: {e.response.text}")
        return None

    verification_uri = device_auth_data.get('verification_uri_complete') or device_auth_data.get('verification_uri')
    user_code = device_auth_data.get('user_code')
    device_code = device_auth_data.get('device_code')
    expires_in = device_auth_data.get('expires_in')
    interval = device_auth_data.get('interval', 5) # Default polling interval

    if not (verification_uri and user_code and device_code):
        print("Error: Could not retrieve all necessary data from device auth endpoint.")
        print(f"Received: {device_auth_data}")
        return None

    print("\n" + "="*50)
    print("ACTION REQUIRED:")
    print(f"1. Open the following URL in your browser: {verification_uri}")
    print(f"2. When prompted, enter the code: {user_code}")
    print(f"You have approximately {expires_in // 60} minutes to complete this.")
    print("="*50 + "\n")
    print(f"Polling for token every {interval} seconds...")

    # 2. Token Polling
    polling_start_time = time.time()
    while True:
        if time.time() - polling_start_time > expires_in:
            print("Error: Device authorization flow expired.")
            return None

        time.sleep(interval)
        print("Polling for token...")
        token_payload = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'client_id': SDK_CLIENT_ID,
            'device_code': device_code
        }
        try:
            token_response = requests.post(token_endpoint, data=token_payload, timeout=10)
            token_data = token_response.json()

            if token_response.status_code == 200 and 'access_token' in token_data:
                print("\nSuccessfully obtained tokens!")
                # print(json.dumps(token_data, indent=2))
                return token_data.get('access_token')
            elif token_data.get('error') == 'authorization_pending':
                print("Authorization still pending...")
                # Optional: increase interval based on Keycloak's hint if provided
            elif token_data.get('error') == 'slow_down':
                print("Slowing down polling as requested by server...")
                time.sleep(interval) # Or use a server-hinted increased interval
            elif token_data.get('error'):
                print(f"Error obtaining token: {token_data.get('error_description') or token_data.get('error')}")
                return None
            else:
                token_response.raise_for_status() # For other unexpected errors

        except requests.exceptions.RequestException as e:
            print(f"Error during token polling: {e}")
            # Continue polling unless it's a fatal client error
            time.sleep(interval) # Wait before retrying


def call_protected_api(access_token: str):
    """
    Calls the protected API in app1 using the obtained access token.
    """
    if not access_token:
        print("No access token provided. Cannot call API.")
        return

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json'
    }
    
    print(f"\nCalling API: GET {API_DATA_ENDPOINT}")
    try:
        response = requests.get(API_DATA_ENDPOINT, headers=headers, timeout=10)
        if response.status_code == 200:
            print("API call successful!")
            print("Response data:")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"API call failed with status {response.status_code}:")
            try:
                print(json.dumps(response.json(), indent=2))
            except json.JSONDecodeError:
                print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"Error calling API: {e}")


if __name__ == "__main__":
    print("Starting SDK/CLI Demo for Keycloak Authentication (Device Flow)")
    access_token = run_device_authorization_flow()

    if access_token:
        print(f"\nAccess Token (first 20 chars): {access_token[:20]}...")
        call_protected_api(access_token)
    else:
        print("\nFailed to obtain access token. API call will not be made.")