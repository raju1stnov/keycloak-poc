import os
# import time , uuid # uuid and time not used directly in this simplified version
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth, OAuthError
from dotenv import load_dotenv
from urllib.parse import urlencode

load_dotenv()

APP_NAME = "App 2 (FastAPI)" # Specific to App 2

app = FastAPI()

# Session Middleware
# SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", os.urandom(24).hex()) # Defined in docker-compose
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", "default-insecure-secret-app2"), # Ensure unique default if not set by env
    https_only=False,  # Allow cookies over HTTP for local dev
    same_site="lax"    # Relax same-site policy for local testing
)

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

# --- OAuth Client Configuration (for app2) ---
oauth = OAuth()

APP_BASE_URL = os.getenv('APP_BASE_URL', 'http://localhost:8092') # Default for app2
# Public Issuer URL - MUST match 'iss' claim in ID Token from Keycloak.
# docker-compose.yml for app2 should set this to http://localhost:8080/realms/poc-realm
OIDC_PUBLIC_ISSUER_URL = os.getenv('OIDC_ISSUER_URL', 'http://localhost:8080/realms/poc-realm')

# Internal base URL for Keycloak (for server-to-server calls from app2 to keycloak container)
KEYCLOAK_INTERNAL_BASE_URL = "http://keycloak:8080" # Assuming 'keycloak' is the service name in Docker
KEYCLOAK_REALM_NAME = os.getenv('KEYCLOAK_REALM_NAME', 'poc-realm') # Should be consistent

OIDC_CLIENT_ID = os.getenv('OIDC_CLIENT_ID', 'app2-fastapi-client') # Set by docker-compose for app2
OIDC_CLIENT_SECRET = os.getenv('OIDC_CLIENT_SECRET', 'app2-secret') # Set by docker-compose for app2

print(f"DEBUG {APP_NAME}: Public OIDC_ISSUER_URL for server_metadata: '{OIDC_PUBLIC_ISSUER_URL}'")

# Manually construct the server_metadata for App 2.
server_metadata_config_app2 = {
    "issuer": OIDC_PUBLIC_ISSUER_URL,  # CRITICAL: Set to the public issuer URL
    "authorization_endpoint": f"{OIDC_PUBLIC_ISSUER_URL}/protocol/openid-connect/auth",
    # For token, userinfo, jwks_uri, app2 (server-side) calls Keycloak INTERNALLY
    "token_endpoint": f"{KEYCLOAK_INTERNAL_BASE_URL}/realms/{KEYCLOAK_REALM_NAME}/protocol/openid-connect/token",
    "userinfo_endpoint": f"{KEYCLOAK_INTERNAL_BASE_URL}/realms/{KEYCLOAK_REALM_NAME}/protocol/openid-connect/userinfo",
    "jwks_uri": f"{KEYCLOAK_INTERNAL_BASE_URL}/realms/{KEYCLOAK_REALM_NAME}/protocol/openid-connect/certs",
    # Public URL for browser-initiated logout
    "end_session_endpoint": f"{OIDC_PUBLIC_ISSUER_URL}/protocol/openid-connect/logout",
    # --- Add other common fields from a typical .well-known/openid-configuration ---
    # You should check your Keycloak's actual discovery doc and add more if Authlib needs them.
    "response_types_supported": ["code", "none", "id_token", "token id_token", "code id_token", "code token", "code token id_token"],
    "subject_types_supported": ["public", "pairwise"],
    "id_token_signing_alg_values_supported": [
        "PS384", "ES384", "RS384", "HS256", "HS512", "ES256", "RS256", "HS384", "ES512", "PS256", "PS512"
    ],
    "token_endpoint_auth_methods_supported": [
        "private_key_jwt", "client_secret_post", "client_secret_basic", "client_secret_jwt", "tls_client_auth"
    ],
    "scopes_supported": ["openid", "email", "profile", "roles", "offline_access"], # "roles" might not be used by app2 UI
    "claims_supported": ["sub", "iss", "auth_time", "name", "given_name", "family_name", "preferred_username", "email"],
}
print(f"DEBUG {APP_NAME}: server_metadata_config_app2 being passed to oauth.register: {server_metadata_config_app2}")

oauth.register(
    name='keycloak', # Keep name consistent if using oauth.keycloak later
    client_id=OIDC_CLIENT_ID,
    client_secret=OIDC_CLIENT_SECRET,

    # Provide the constructed metadata directly:
    server_metadata=server_metadata_config_app2,

    # Explicitly provide key URLs derived from our server_metadata_config_app2.
    authorize_url=server_metadata_config_app2['authorization_endpoint'],
    access_token_url=server_metadata_config_app2['token_endpoint'],
    userinfo_endpoint=server_metadata_config_app2['userinfo_endpoint'], # For fetching user info
    jwks_uri=server_metadata_config_app2['jwks_uri'],                   # For ID token validation

    client_kwargs={
        'scope': 'openid email profile', # Basic scopes for a UI client
        'token_endpoint_auth_method': 'client_secret_post',
    }
)

@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request):
    user = request.session.get('user_app2') # Use namespaced session key
    # Pass the error to the template if it exists in the session (e.g., from a failed callback)
    error = request.session.pop('error_app2', None)
    return templates.TemplateResponse("index.html", {"request": request, "user": user, "app_name": APP_NAME, "error": error})

@app.get("/login")
async def login(request: Request):
    redirect_uri = f"{APP_BASE_URL}/auth/callback"
    print(f"{APP_NAME}: Login redirect_uri: {redirect_uri}")

    # ---- START DEBUG in /login ----
    auth_url_on_client = "NOT ACCESSIBLE"
    if hasattr(oauth, 'keycloak') and oauth.keycloak:
        auth_url_on_client = getattr(oauth.keycloak, 'authorize_url', 'ATTRIBUTE authorize_url NOT FOUND')
    print(f"DEBUG {APP_NAME}: In /login, effective oauth.keycloak.authorize_url: '{auth_url_on_client}'")
    # ---- END DEBUG in /login ----

    starlette_redirect_response = await oauth.keycloak.authorize_redirect(
        request,
        redirect_uri
    )
    # ---- START DEBUG: Verify state in session IMMEDIATELY ----
    auth_redirect_target_url = starlette_redirect_response.headers.get('location')
    print(f"DEBUG {APP_NAME}: Redirecting to Keycloak URL: {auth_redirect_target_url}")
    generated_state_for_redirect = None
    if auth_redirect_target_url:
        try:
            from urllib.parse import urlparse, parse_qs # ensure imported
            parsed_auth_url = urlparse(auth_redirect_target_url)
            query_params_auth_url = parse_qs(parsed_auth_url.query)
            generated_state_for_redirect = query_params_auth_url.get('state', [None])[0]
            print(f"DEBUG {APP_NAME}: State generated by authorize_redirect for this flow: '{generated_state_for_redirect}'")
        except Exception as e:
            print(f"DEBUG {APP_NAME}: Error parsing state from redirect URL: {e}")
    print(f"DEBUG {APP_NAME}: Session contents IMMEDIATELY AFTER authorize_redirect call in /login: {dict(request.session)}")
    if generated_state_for_redirect:
        expected_session_key_format_by_authlib = f'_state_keycloak_{generated_state_for_redirect}'
        if expected_session_key_format_by_authlib in request.session:
            print(f"DEBUG {APP_NAME}: State '{generated_state_for_redirect}' IS CONFIRMED in session with key '{expected_session_key_format_by_authlib}' before redirecting.")
        else:
            print(f"DEBUG {APP_NAME}: State '{generated_state_for_redirect}' IS MISSING from session using key '{expected_session_key_format_by_authlib}' right after authorize_redirect.")
    # ---- END NEW DEBUG ----
    return starlette_redirect_response

@app.get("/auth/callback")
async def auth_callback(request: Request):
    print(f"{APP_NAME}: Callback - Raw URL: {str(request.url)}")
    # ... (add other basic callback logging as in app1 if desired)

    # ---- START DEBUG for server_metadata and specific attributes ----
    # (Similar debug block as in app1's callback can be added here if needed for deep troubleshooting)
    # ---- END DEBUG ----
    try:
        token = await oauth.keycloak.authorize_access_token(request)
    except OAuthError as error:
        print(f"{APP_NAME}: Error during token authorization: {error.description} (Error details: {error.error})")
        # Store error in session to display on homepage
        request.session['error_app2'] = f"Authentication failed: {error.description}"
        return RedirectResponse(url=request.url_for('homepage'), status_code=302)
    except JoseError as error: # Catch specific JoseErrors if not wrapped by OAuthError
        print(f"{APP_NAME}: JoseError during token processing: {error}")
        request.session['error_app2'] = f"Token processing failed: {error}"
        return RedirectResponse(url=request.url_for('homepage'), status_code=302)

    user_info = token.get('userinfo') # This is populated by parse_id_token within authorize_access_token
    if user_info:
        request.session['user_app2'] = dict(user_info) # Namespace session

    # Optionally store tokens if app2 needs to make API calls (not currently implemented for app2)
    # request.session['id_token_app2'] = token.get('id_token')
    # request.session['access_token_app2'] = token.get('access_token')

    return RedirectResponse(url=request.url_for('profile'), status_code=302)

@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request):
    user = request.session.get('user_app2')
    # access_token_app2 = request.session.get('access_token_app2') # If app2 needed to show/use it
    if not user:
        return RedirectResponse(url=request.url_for('login'), status_code=302)
    return templates.TemplateResponse("profile.html", {
        "request": request, "user": user, "app_name": APP_NAME,
        # "token": access_token_app2 # Only if profile.html for app2 uses it
    })

@app.get("/logout")
async def logout(request: Request):
    # id_token_hint_app2 = request.session.pop('id_token_app2', None) # If storing ID token
    request.session.pop('user_app2', None)
    # request.session.pop('access_token_app2', None) # If storing access token

    # Use OIDC_PUBLIC_ISSUER_URL for constructing logout URL
    keycloak_logout_url_base = f"{OIDC_PUBLIC_ISSUER_URL}/protocol/openid-connect/logout"
    post_logout_redirect_uri = f"{APP_BASE_URL}/" # Redirect to app2's home

    params = {
        'post_logout_redirect_uri': post_logout_redirect_uri,
        'client_id': OIDC_CLIENT_ID # Use the generic OIDC_CLIENT_ID for app2
    }
    # if id_token_hint_app2:
    #     params['id_token_hint'] = id_token_hint_app2

    logout_url = f"{keycloak_logout_url_base}?{urlencode(params)}"
    return RedirectResponse(url=logout_url, status_code=302)

if __name__ == "__main__":
    import uvicorn
    # These setdefault calls are for running app2.py directly (e.g. python app2/main.py)
    # When run with Docker Compose, the environment variables from docker-compose.yml take precedence.
    os.environ.setdefault('OIDC_CLIENT_ID', 'app2-fastapi-client')
    os.environ.setdefault('OIDC_CLIENT_SECRET', 'app2-secret')
    os.environ.setdefault('APP_BASE_URL', 'http://localhost:8092')
    # For OIDC_ISSUER_URL, if running directly, ensure it points to the public Keycloak URL
    # or rely on the script's global default if not overridden by .env or direct env setting.
    # The global OIDC_PUBLIC_ISSUER_URL will use its default if 'OIDC_ISSUER_URL' env var is not set.
    # This is fine, as the default is the correct public URL.
    os.environ.setdefault('KEYCLOAK_REALM_NAME', 'poc-realm')
    os.environ.setdefault('SESSION_SECRET_KEY', 'another-default-insecure-secret-for-app2')


    uvicorn.run(app, host="0.0.0.0", port=8000)