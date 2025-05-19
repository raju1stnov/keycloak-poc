from keycloak import KeycloakAdmin, KeycloakOpenIDConnection
import os

KEYCLOAK_SERVER_URL = "http://localhost:8080" 
KEYCLOAK_REALM_NAME = "poc-realm"
KEYCLOAK_ADMIN_USER = "admin"
KEYCLOAK_ADMIN_PASSWORD = "admin"
KEYCLOAK_API_CLIENT_ID = "admin-cli"

try:
    # Connect to master realm first
    keycloak_connection = KeycloakOpenIDConnection(
        server_url=KEYCLOAK_SERVER_URL,
        username=KEYCLOAK_ADMIN_USER,
        password=KEYCLOAK_ADMIN_PASSWORD,
        realm_name="master",
        client_id=KEYCLOAK_API_CLIENT_ID,
        verify=True
    )

    keycloak_admin = KeycloakAdmin(connection=keycloak_connection)
    
    print(f"Connected to Keycloak admin API at {KEYCLOAK_SERVER_URL}")

    # Switch to target realm context
    keycloak_admin.realm_name = KEYCLOAK_REALM_NAME

    print(f"\n--- Users in '{KEYCLOAK_REALM_NAME}' realm ---")
    users = keycloak_admin.get_users()
    if users:
        for user in users:
            print(f"  ID: {user['id']}, Username: {user['username']}, Email: {user.get('email', 'N/A')}")
    else:
        print("No users found")

    print(f"\n--- Realm Info for '{KEYCLOAK_REALM_NAME}' ---")
    try:
        realm_info = keycloak_admin.get_realm(realm_name=KEYCLOAK_REALM_NAME)
        print(f"  Realm ID: {realm_info['id']}")
        print(f"  Display Name: {realm_info.get('displayName', 'N/A')}")
        print(f"  Enabled: {realm_info['enabled']}")
    except Exception as e:
        print(f"Error fetching realm info: {e}")

    print(f"\n--- Clients in '{KEYCLOAK_REALM_NAME}' realm ---")
    clients = keycloak_admin.get_clients()
    if clients:
        for client in clients:
            print(f"  Client ID: {client['clientId']}, Enabled: {client['enabled']}")
    else:
        print("No clients found")

except Exception as e:
    print(f"An error occurred: {e}")
    print("Troubleshooting steps:")
    print("1. Verify Keycloak is running and accessible at", KEYCLOAK_SERVER_URL)
    print("2. Check admin credentials (username/password)")
    print("3. Ensure the realm exists in Keycloak")
    print("4. Confirm python-keycloak version (should be >= 2.16.0)")