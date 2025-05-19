import os
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth, OAuthError
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.jose import JsonWebKey, JsonWebToken, JoseError # Ensure JsonWebKey is imported
from dotenv import load_dotenv
from urllib.parse import urlencode
from pydantic import BaseModel
import casbin
import httpx # For fetching JWKS
from urllib.parse import urlparse, parse_qs

load_dotenv()

APP_NAME = "App 1 (FastAPI)" # Specific to App 1

app = FastAPI()

# Session Middleware for storing OIDC state and user info
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", os.urandom(24).hex()) # Use env var or generate
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", "default-insecure-secret"),
    https_only=False,  # Allow cookies over HTTP
    same_site="lax"    # Relax same-site policy for local testing
)

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

# --- OAuth Client Configuration (for app1's own login) ---
oauth = OAuth()

APP_BASE_URL = os.getenv('APP_BASE_URL', 'http://localhost:8091')
# Public Issuer URL - this is what Keycloak puts in token's 'iss' & what we need for validation
OIDC_ISSUER_URL = os.getenv('OIDC_ISSUER_URL', 'http://localhost:8080/realms/poc-realm')
# Browser-facing base URL for Keycloak (can be same as OIDC_ISSUER_URL without /protocol/...)
# KEYCLOAK_BROWSER_BASE_URL = OIDC_ISSUER_URL.rsplit('/realms', 1)[0] # e.g., http://localhost:8080 (Not strictly needed if OIDC_ISSUER_URL is used for public endpoints)
# Internal base URL for Keycloak (for server-to-server calls from app1 to keycloak container)
KEYCLOAK_INTERNAL_BASE_URL = "http://keycloak:8080" # Assuming 'keycloak' is the service name in Docker
KEYCLOAK_REALM_NAME = os.getenv('KEYCLOAK_REALM_NAME', 'poc-realm') # Get realm from env or default

KEYCLOAK_CLIENT_ID = os.getenv('OIDC_CLIENT_ID', 'app1-fastapi-client')
KEYCLOAK_CLIENT_SECRET = os.getenv('OIDC_CLIENT_SECRET', 'app1-secret')

# Using OIDC_ISSUER_URL directly as it already includes the realm path for public endpoints.
# KEYCLOAK_INTERNAL_ISSUER_URL is defined but used mainly by KeycloakTokenValidator or for clarity if preferred.
# KEYCLOAK_INTERNAL_ISSUER_URL = "http://keycloak:8080/realms/poc-realm"


print(f"DEBUG app1: Value of OIDC_ISSUER_URL (public issuer) for server_metadata: '{OIDC_ISSUER_URL}'")

# Manually construct the server_metadata.
# This dictionary will be used by Authlib instead of fetching from server_metadata_url.
server_metadata_config = {
    "issuer": OIDC_ISSUER_URL,  # CRITICAL: Set to the public issuer URL
    "authorization_endpoint": f"{OIDC_ISSUER_URL}/protocol/openid-connect/auth",
    # For token, userinfo, jwks_uri, app1 (server-side) calls Keycloak INTERNALLY
    "token_endpoint": f"{KEYCLOAK_INTERNAL_BASE_URL}/realms/{KEYCLOAK_REALM_NAME}/protocol/openid-connect/token",
    "userinfo_endpoint": f"{KEYCLOAK_INTERNAL_BASE_URL}/realms/{KEYCLOAK_REALM_NAME}/protocol/openid-connect/userinfo",
    "jwks_uri": f"{KEYCLOAK_INTERNAL_BASE_URL}/realms/{KEYCLOAK_REALM_NAME}/protocol/openid-connect/certs",
    # Public URL for browser-initiated logout
    "end_session_endpoint": f"{OIDC_ISSUER_URL}/protocol/openid-connect/logout",
    # --- Add other common fields from a typical .well-known/openid-configuration ---
    # You MUST check your Keycloak's actual discovery doc and add more if Authlib needs them.
    "response_types_supported": ["code", "none", "id_token", "token id_token", "code id_token", "code token", "code token id_token"],
    "subject_types_supported": ["public", "pairwise"],
    "id_token_signing_alg_values_supported": [
        "PS384", "ES384", "RS384", "HS256", "HS512", "ES256", "RS256", "HS384", "ES512", "PS256", "PS512"
    ],
    "token_endpoint_auth_methods_supported": [
        "private_key_jwt", "client_secret_post", "client_secret_basic", "client_secret_jwt", "tls_client_auth"
    ],
    "scopes_supported": ["openid", "email", "profile", "roles", "offline_access", "address", "phone", "web-origins", "microprofile-jwt"],
    "claims_supported": ["sub", "iss", "auth_time", "name", "given_name", "family_name", "preferred_username", "email"],
    # Example: Add more fields based on your Keycloak's discovery document
    # "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "password", "client_credentials"],
    # "code_challenge_methods_supported": ["plain", "S256"]
}
print(f"DEBUG app1: server_metadata_config being passed to oauth.register: {server_metadata_config}")


oauth.register(
    name='keycloak',
    client_id=KEYCLOAK_CLIENT_ID,
    client_secret=KEYCLOAK_CLIENT_SECRET,
    # Provide the constructed metadata directly:
    server_metadata=server_metadata_config,
    authorize_url=server_metadata_config['authorization_endpoint'],
    access_token_url=server_metadata_config['token_endpoint'],
    userinfo_endpoint=server_metadata_config['userinfo_endpoint'],
    jwks_uri=server_metadata_config['jwks_uri'],
    # Individual endpoint URLs (authorize_url, access_token_url, etc.) and server_metadata_url
    # are removed as Authlib will derive them from the provided 'server_metadata'.
    client_kwargs={
        'scope': 'openid email profile roles', # This is still essential for the client to request.
        'token_endpoint_auth_method': 'client_secret_post', # Or 'client_secret_basic' as per your Keycloak client config
    }
)

# --- Casbin Setup ---
CASBIN_MODEL_PATH = os.path.join(os.path.dirname(__file__), "casbin_model.conf")
CASBIN_POLICY_PATH = os.path.join(os.path.dirname(__file__), "casbin_policy.csv")

try:
    enforcer = casbin.Enforcer(CASBIN_MODEL_PATH, CASBIN_POLICY_PATH)
except Exception as e:
    print(f"CRITICAL: Failed to initialize Casbin enforcer: {e}")
    enforcer = None


# --- API Token Validation (Resource Server part) ---
http_bearer_scheme = HTTPBearer()
# _jwk_set_cache = None # This global is not directly used by the class as written (it uses self._jwk_set_cache)

class KeycloakTokenValidator(BearerTokenValidator):
    def __init__(self):
        super().__init__(realm=KEYCLOAK_REALM_NAME) # Use KEYCLOAK_REALM_NAME
        self.public_issuer_url = OIDC_ISSUER_URL
        # For fetching JWKS, KeycloakTokenValidator does its own discovery using internal URLs
        self.internal_keycloak_issuer_url_for_discovery = f"{KEYCLOAK_INTERNAL_BASE_URL}/realms/{KEYCLOAK_REALM_NAME}"
        self.internal_keycloak_base_for_jwks_rewrite = KEYCLOAK_INTERNAL_BASE_URL
        self.public_keycloak_base_for_jwks_rewrite = OIDC_ISSUER_URL.split('/realms')[0]

        self.issuer_url = self.public_issuer_url # For validating 'iss' in API tokens
        self.internal_oidc_config_url = f"{self.internal_keycloak_issuer_url_for_discovery}/.well-known/openid-configuration"
        self.allowed_audiences = os.getenv("ALLOWED_AUDIENCES", "account").split(',')
        self._jwk_set_cache = None # Instance cache

    async def get_jwk_set(self):
        if self._jwk_set_cache is None:
            try:
                async with httpx.AsyncClient(verify=False) as client:
                    resp_oidc_config = await client.get(self.internal_oidc_config_url)
                    resp_oidc_config.raise_for_status()
                    oidc_config = resp_oidc_config.json()

                    jwks_uri_from_config = oidc_config.get("jwks_uri")
                    if not jwks_uri_from_config:
                        raise ValueError("jwks_uri not found in OIDC config")

                    actual_jwks_uri_to_fetch = jwks_uri_from_config
                    if self.public_keycloak_base_for_jwks_rewrite and jwks_uri_from_config.startswith(self.public_keycloak_base_for_jwks_rewrite):
                        actual_jwks_uri_to_fetch = jwks_uri_from_config.replace(
                            self.public_keycloak_base_for_jwks_rewrite,
                            self.internal_keycloak_base_for_jwks_rewrite
                        )
                    resp_jwks = await client.get(actual_jwks_uri_to_fetch)
                    resp_jwks.raise_for_status()
                    self._jwk_set_cache = JsonWebKey.import_key_set(resp_jwks.json())
            except Exception as e:
                print(f"Failed to fetch or parse JWKS for API token validation: {e}")
                self._jwk_set_cache = None
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Could not fetch JWKS: {e}")
        return self._jwk_set_cache

    async def authenticate_token(self, token_string: str):
        try:
            jwk_set = await self.get_jwk_set()
            if not jwk_set:
                raise JoseError("JWKS not available for API token validation.")

            jwt_decoder = JsonWebToken(['RS256'])
            claims_options = {
                "iss": {"essential": True, "value": self.issuer_url}, # Expect public issuer
            }
            claims = jwt_decoder.decode(token_string, key=jwk_set, claims_options=claims_options)

            token_aud = claims.get('aud')
            if isinstance(token_aud, str): token_aud = [token_aud]
            is_aud_valid = False
            if token_aud:
                valid_audiences_for_api = self.allowed_audiences + [KEYCLOAK_CLIENT_ID]
                for aud in token_aud:
                    if aud in valid_audiences_for_api:
                        is_aud_valid = True
                        break
            if not is_aud_valid and token_aud:
                print(f"API Token audience {claims.get('aud')} not in allowed {valid_audiences_for_api}")
                # raise JoseError("Invalid audience for API token") # Uncomment for strict check

            claims.validate()
            return claims
        except JoseError as e:
            print(f"API Token validation JoseError: {e}")
            return None
        except Exception as e:
            print(f"Generic API token validation error: {e}")
            return None

keycloak_token_validator = KeycloakTokenValidator()

async def get_current_api_user(credentials: HTTPAuthorizationCredentials = Depends(http_bearer_scheme)):
    token_string = credentials.credentials
    claims = await keycloak_token_validator.authenticate_token(token_string)
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API token",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )
    username = claims.get("preferred_username")
    roles = claims.get("realm_access", {}).get("roles", [])
    if not username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Username not found in API token.")
    return {"username": username, "roles": roles, "claims": claims}


# --- Frontend Routes (OIDC Client part) ---
@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request):
    user = request.session.get('user')
    return templates.TemplateResponse("index.html", {"request": request, "user": user, "app_name": APP_NAME})

@app.get("/login")
async def login(request: Request):
    import time
    current_time = time.time()
    session_keys_to_delete = []
    for key in request.session.keys():
        if key.startswith('_state_keycloak_'):
            state_data = request.session.get(key)
            if state_data and state_data.get('exp', 0) < current_time:
                session_keys_to_delete.append(key)
    for key in session_keys_to_delete:
        del request.session[key]

    session_states = [key for key in request.session.keys() if key.startswith('_state_keycloak_')]
    for state_key in session_states:
        state_data = request.session.get(state_key)
        if state_data and state_data.get('exp', 0) < current_time:
            del request.session[state_key]
    redirect_uri = f"{APP_BASE_URL}/auth/callback"
    print(f"{APP_NAME}: Login redirect_uri: {redirect_uri}")

    # ---- START DEBUG in /login (existing) ----
    auth_url_on_client = "NOT ACCESSIBLE"
    token_url_on_client = "NOT ACCESSIBLE"
    if hasattr(oauth, 'keycloak') and oauth.keycloak:
        auth_url_on_client = getattr(oauth.keycloak, 'authorize_url', 'ATTRIBUTE authorize_url NOT FOUND')
        token_url_on_client = getattr(oauth.keycloak, 'access_token_url', 'ATTRIBUTE access_token_url NOT FOUND')
        if token_url_on_client == 'ATTRIBUTE access_token_url NOT FOUND':
             token_url_on_client = getattr(oauth.keycloak, 'token_endpoint', 'ATTRIBUTE token_endpoint NOT FOUND')
    print(f"DEBUG app1: In /login, effective oauth.keycloak.authorize_url: '{auth_url_on_client}'")
    print(f"DEBUG app1: In /login, effective oauth.keycloak token exchange URL: '{token_url_on_client}'")
    # ---- END DEBUG in /login (existing) ----

    # This call generates the state and is supposed to save it in request.session
    # It returns a Starlette RedirectResponse object
    starlette_redirect_response = await oauth.keycloak.authorize_redirect(
        request,
        redirect_uri
    )

    # ---- START NEW DEBUG: Verify state in session IMMEDIATELY ----
    # The actual redirect URL is in the 'location' header of the response
    auth_redirect_target_url = starlette_redirect_response.headers.get('location')
    print(f"DEBUG app1: Redirecting to Keycloak URL: {auth_redirect_target_url}")

    generated_state_for_redirect = None
    if auth_redirect_target_url:
        try:
            parsed_auth_url = urlparse(auth_redirect_target_url)
            query_params_auth_url = parse_qs(parsed_auth_url.query)
            generated_state_for_redirect = query_params_auth_url.get('state', [None])[0]
            print(f"DEBUG app1: State generated by authorize_redirect for this flow: '{generated_state_for_redirect}'")
        except Exception as e:
            print(f"DEBUG app1: Error parsing state from redirect URL: {e}")

    print(f"DEBUG app1: Session contents IMMEDIATELY AFTER authorize_redirect call in /login: {dict(request.session)}") # Log a copy

    if generated_state_for_redirect:
        # Authlib stores state in session with key like '_state_{name}_{state_val}'
        # However, the StarletteIntegration uses a slightly different key format initially before setting the cookie.
        # The key used by StarletteIntegration's save_authorize_state is `_state_key_{name}_{state}`
        # Let's check for the key that authorize_access_token would look for: `_state_{name}_{state}` (after framework processing)
        # More accurately, the key saved by StarletteIntegration.save_authorize_state is f'_state_{self.name}_{state}'
        # where self.name is 'keycloak'.
        # Let's also just check if the state *value* can be found in any of the session data values for now,
        # as the exact internal keying for the temp state vs final session state might differ.

        # The key that authorize_access_token uses to pop the state is actually constructed from the state coming back
        # in the callback URL: `session_key = f'_state_{self.name}_{params[self._state_param_name]}'`
        # For now, the most important thing is to see if the *new* state is being added to the session dict *at all*.

        # Let's directly check the session key Authlib will form.
        # The 'state' is stored in the session by StarletteIntegration using:
        # `session[key] = {'data': data, 'exp': current_time + self.OAUTH_STATE_EXPIRES_IN}`
        # where key = `f'_state_{self.name}_{state}'`
        # So, self.name is 'keycloak'.
        expected_session_key_format_by_authlib = f'_state_keycloak_{generated_state_for_redirect}'

        if expected_session_key_format_by_authlib in request.session:
            print(f"DEBUG app1: State '{generated_state_for_redirect}' IS CONFIRMED in session with key '{expected_session_key_format_by_authlib}' before redirecting.")
            print(f"DEBUG app1: Data for this state in session: {request.session[expected_session_key_format_by_authlib]}")
        else:
            print(f"DEBUG app1: State '{generated_state_for_redirect}' IS MISSING from session using key '{expected_session_key_format_by_authlib}' right after authorize_redirect. THIS IS THE PROBLEM POINT.")
            all_session_keys = list(request.session.keys())
            print(f"DEBUG app1: All current session keys: {all_session_keys}")
    else:
        print("DEBUG app1: Could not parse 'state' from the authorization_url for detailed session check.")
    # ---- END NEW DEBUG ----

    return starlette_redirect_response # Return the Starlette RedirectResponse object
    

@app.get("/auth/callback")
async def auth_callback(request: Request):
    print(f"{APP_NAME}: Callback - Raw URL: {str(request.url)}")
    print(f"{APP_NAME}: Callback - Query params received (raw): {request.url.query}")
    print(f"{APP_NAME}: Callback - Query params received (parsed dict): {dict(request.query_params)}")
    print(f"{APP_NAME}: Callback - State from query: {request.query_params.get('state')}")
    print(f"{APP_NAME}: Callback - Code from query: {request.query_params.get('code')}")
    print(f"{APP_NAME}: Callback - Session contents at callback: {request.session}")

    # ---- START REVISED DEBUG for server_metadata and specific attributes ----
    client_sm_value_str = "oauth.keycloak.server_metadata NOT ACCESSIBLE or None"
    client_sm_issuer = "NOT FOUND IN METADATA"
    client_sm_jwks_uri = "NOT FOUND IN METADATA"
    jwks_uri_direct_attr = "oauth.keycloak.jwks_uri NOT ACCESSIBLE or None"

    if hasattr(oauth, 'keycloak') and oauth.keycloak:
        # Get the direct value of the server_metadata attribute
        raw_metadata = getattr(oauth.keycloak, 'server_metadata', None)
        if raw_metadata is not None:
            client_sm_value_str = str(raw_metadata)[:500] # Print raw value (truncated)
            if isinstance(raw_metadata, dict):
                # Check if it's nested under a 'server_metadata' key
                if 'server_metadata' in raw_metadata and isinstance(raw_metadata['server_metadata'], dict):
                    actual_metadata_dict = raw_metadata['server_metadata']
                    print("DEBUG app1: server_metadata attribute appears nested. Accessing inner dict.")
                else:
                    actual_metadata_dict = raw_metadata # Assume it's the flat dict
                    print("DEBUG app1: server_metadata attribute appears flat.")

                client_sm_issuer = actual_metadata_dict.get('issuer', 'issuer key NOT FOUND')
                client_sm_jwks_uri = actual_metadata_dict.get('jwks_uri', 'jwks_uri key NOT FOUND')
            else:
                client_sm_value_str += " (Note: not a dict)"
        
        # Check if jwks_uri is a direct attribute on the client (due to explicit registration)
        jwks_uri_direct_attr = getattr(oauth.keycloak, 'jwks_uri', 'ATTRIBUTE jwks_uri NOT FOUND')

    print(f"DEBUG app1: Raw oauth.keycloak.server_metadata attribute (first 500 chars): {client_sm_value_str}")
    print(f"DEBUG app1: Issuer from effective server_metadata: '{client_sm_issuer}'")
    print(f"DEBUG app1: JWKS URI from effective server_metadata: '{client_sm_jwks_uri}'")
    print(f"DEBUG app1: Direct oauth.keycloak.jwks_uri attribute: '{jwks_uri_direct_attr}'")
    # ---- END REVISED DEBUG ----

    try:
        token = await oauth.keycloak.authorize_access_token(request)
    except OAuthError as error:
        print(f"{APP_NAME}: Error during token authorization: {error.description}")
        return templates.TemplateResponse("index.html", {
            "request": request, "user": None, "app_name": APP_NAME,
            "error": f"Authentication failed: {error.description}"
        })
    except JoseError as error:
        print(f"{APP_NAME}: JoseError during token processing: {error}")
        return templates.TemplateResponse("index.html", {
            "request": request, "user": None, "app_name": APP_NAME,
            "error": f"Authentication token processing failed: {error}"
        })

    user_info = token.get('userinfo')
    if user_info:
        request.session['user'] = dict(user_info)
    request.session['id_token'] = token.get('id_token')
    request.session['access_token'] = token.get('access_token')
    return RedirectResponse(url=request.url_for('profile'), status_code=302)

@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request):
    user = request.session.get('user')
    access_token = request.session.get('access_token')
    if not user:
        return RedirectResponse(url=request.url_for('login'), status_code=302)
    return templates.TemplateResponse("profile.html", {
        "request": request, "user": user, "app_name": APP_NAME,
        "token": access_token
    })

@app.get("/logout")
async def logout(request: Request):
    id_token_hint = request.session.pop('id_token', None)
    request.session.pop('user', None)
    request.session.pop('access_token', None)

    # CRITICAL FIX: Use OIDC_ISSUER_URL for constructing logout URL
    keycloak_logout_url_base = f"{OIDC_ISSUER_URL}/protocol/openid-connect/logout"
    post_logout_redirect_uri = f"{APP_BASE_URL}/"

    params = {
        'post_logout_redirect_uri': post_logout_redirect_uri,
        'client_id': KEYCLOAK_CLIENT_ID
    }
    if id_token_hint:
        params['id_token_hint'] = id_token_hint

    logout_url = f"{keycloak_logout_url_base}?{urlencode(params)}"
    return RedirectResponse(url=logout_url, status_code=302)

# --- Backend API Routes (Resource Server with Casbin) ---
class ApiData(BaseModel):
    id: str
    name: str
    value: str

api_data_store = {
    "item1": {"id": "item1", "name": "Sample Item Alpha", "value": "This is a test item."},
    "item2": {"id": "item2", "name": "Sample Item Beta", "value": "Another piece of data."}
}

@app.get("/api/data", response_model=list[ApiData])
async def get_all_api_data(request: Request, current_user: dict = Depends(get_current_api_user)):
    if not enforcer:
        raise HTTPException(status_code=500, detail="Casbin enforcer not initialized")
    subject = current_user["username"]
    obj = "/api/data"
    act = "GET"
    authorized_direct = enforcer.enforce(subject, obj, act)
    authorized_role = any(enforcer.enforce(role, obj, act) for role in current_user["roles"])
    if not (authorized_direct or authorized_role):
        print(f"AuthZ DENIED: User '{subject}' (roles: {current_user['roles']}) to {act} {obj}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to GET data")
    print(f"AuthZ ALLOWED: User '{subject}' (roles: {current_user['roles']}) to {act} {obj}")
    return list(api_data_store.values())

@app.post("/api/data", response_model=ApiData, status_code=status.HTTP_201_CREATED)
async def create_api_data(data: ApiData, request: Request, current_user: dict = Depends(get_current_api_user)):
    if not enforcer:
        raise HTTPException(status_code=500, detail="Casbin enforcer not initialized")
    subject = current_user["username"]
    obj = "/api/data"
    act = "POST"
    authorized_direct = enforcer.enforce(subject, obj, act)
    authorized_role = any(enforcer.enforce(role, obj, act) for role in current_user["roles"])
    if not (authorized_direct or authorized_role):
        print(f"AuthZ DENIED: User '{subject}' (roles: {current_user['roles']}) to {act} {obj}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to POST data")
    if data.id in api_data_store:
        raise HTTPException(status_code=400, detail="Data ID already exists")
    api_data_store[data.id] = data.dict()
    print(f"AuthZ ALLOWED: User '{subject}' (roles: {current_user['roles']}) to {act} {obj} - Data created: {data.id}")
    return data

@app.get("/session/debug")
async def debug_session(request: Request):
    return {"session": dict(request.session), "headers": dict(request.headers)}

@app.get("/session/clear")
async def clear_session(request: Request):
    request.session.clear()
    return {"message": "Session cleared"}

# --- Main execution ---
if __name__ == "__main__":
    import uvicorn
    os.environ.setdefault('OIDC_CLIENT_ID', 'app1-fastapi-client')
    os.environ.setdefault('OIDC_CLIENT_SECRET', 'app1-secret')
    os.environ.setdefault('APP_BASE_URL', 'http://localhost:8091')
    # OIDC_ISSUER_URL and KEYCLOAK_REALM_NAME will use defaults or env vars
    uvicorn.run(app, host="0.0.0.0", port=8000)