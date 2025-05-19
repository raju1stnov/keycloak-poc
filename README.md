# keycloak-poc

keycloak-fastapi-poc/
├── docker-compose.yml
├── app1/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py  # FastAPI app
│   └── templates/
│       ├── index.html
│       └── profile.html
├── app2/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py  # FastAPI app
│   └── templates/
│       ├── index.html
│       └── profile.html
├── keycloak_api_demo/
│   ├── requirements.txt
│   └── demo.py
└── README.md


Existing Auth

```mermaid
graph TD
    subgraph Client Layer
        UI[Web UI Client] -->|1 Authenticate| PING
        SDK[CLI/SDK Client] -->|1Authenticate| GOOG
    end

    subgraph Identity Providers
        PING[[PingFederate]]
        GOOG[[Google SDK]]
    end

    subgraph Backend Services
        BE[FastAPI Backend]
        KV[Token Store]
    end

    subgraph Infrastructure
        GKE[Google Kubernetes Engine]
    end

    UI -->|2 Present ID Token| BE
    SDK -->|2 Present ID Token| BE
    BE -->|3a Validate| PING
    BE -->|3b Validate| GOOG
    BE -->|4 Store| KV
    BE -->|5 Issue| SECRET[Secret Token]
    BE -.-> GKE

    classDef component fill:#f9f9f9,stroke:#666,stroke-width:2px;
    classDef cloud fill:#e6f3ff,stroke:#0066cc;
    classDef idp fill:#ffe6e6,stroke:#cc0000;
    class UI,SDK,BE,KV,GKE component;
    class PING,GOOG idp;
    class GKE cloud;
```




**Important:** You will need to replace `YOUR_APP1_FASTAPI_CLIENT_SECRET` and `YOUR_APP2_FASTAPI_CLIENT_SECRET` after you create the clients in Keycloak

```mermaid
graph TD
    subgraph User Interaction
        User_Browser["User (Web Browser)"]
    end

    subgraph Application Services
        App1["FastAPI App 1 (localhost:8091)"]
        App2["FastAPI App 2 (localhost:8092)"]
    end

    subgraph Identity Provider
        Keycloak["Keycloak Server (localhost:8080)"]
    end

    subgraph Admin Tools
        APIDemo["keycloak_api_demo.py"]
    end

    %% User Browser to Applications
    User_Browser -- "1 Accesses App / Initiates Login" --> App1
    User_Browser -- "6 Accesses App / Initiates Login (SSO)" --> App2

    %% Applications to User Browser (Redirects & Content)
    App1 -- "2 Serves Pages / Redirects to Keycloak" --> User_Browser
    App2 -- "7 Serves Pages / Redirects to Keycloak" --> User_Browser

    %% Browser to Keycloak (Authentication)
    User_Browser -- "3 Authenticates at Keycloak UI" --> Keycloak

    %% Keycloak to Browser (Redirects with Code/Session Info)
    Keycloak -- "4 Redirects back to App with Auth Code" --> User_Browser

    %% Applications to Keycloak (Backend Token Exchange)
    App1 -- "5 Exchanges Auth Code for Tokens (OIDC)" --> Keycloak
    App2 -- "8 Exchanges Auth Code for Tokens (OIDC - SSO)" --> Keycloak

    %% API Demo Script to Keycloak
    APIDemo -- "Admin API Calls (e.g., List Users)" --> Keycloak

    %% Style for clarity (optional, but can help)
    classDef app fill:#D6EAF8,stroke:#3498DB,stroke-width:2px;
    classDef idp fill:#D5F5E3,stroke:#2ECC71,stroke-width:2px;
    classDef user fill:#FDEDEC,stroke:#E74C3C,stroke-width:2px;
    classDef admin fill:#FEF9E7,stroke:#F1C40F,stroke-width:2px;

    class User_Browser user;
    class App1,App2 app;
    class Keycloak idp;
    class APIDemo admin;

```

```mermaid
graph TD
    subgraph User Interaction Flow
        User_Browser["User (Web Browser)"]
    end

    subgraph Application Services
        App1["App 1 (localhost:8091) <br> [OIDC Client, API Resource Server, Casbin AuthZ]"]
        App2["App 2 (localhost:8092) <br> [OIDC Client]"]
    end

    subgraph Identity Provider
        Keycloak["Keycloak Server <br> (localhost:8080 for Browser, <br> keycloak:8080 for App1 Backend)"]
    end
  
    subgraph App1_Local_Resources ["(App1 Local Resources)"]
        CasbinFiles["Casbin Policy/Model Files <br> (casbin_policy.csv, casbin_model.conf)"]
    end

    %% App1 - OIDC Login Flow (Authorization Code Flow)
    User_Browser -- "1 Accesses App1, Clicks Login" --> App1
    App1 -- "2 User Agent redirected to Keycloak <br> (via App1's /login, using public authorize_url from server_metadata)" --> User_Browser
    User_Browser -- "3 User authenticates with Credentials at Keycloak UI" --> Keycloak
    Keycloak -- "4 Keycloak redirects User Agent to App1's /auth/callback <br> with Authorization Code" --> User_Browser
    App1 -- "5 App1 (backend) exchanges Authorization Code for Tokens <br> (direct POST to Keycloak's internal token_endpoint from server_metadata)" --> Keycloak
    Keycloak -- "5a ID Token, Access Token, Refresh Token" --> App1
    App1 -- "6 Tokens validated (incl. ID Token 'iss' vs public issuer from server_metadata), <br> User info stored in session, User Agent redirected to /profile" --> User_Browser

    %% App1 - API Call from Profile Page (after login)
    User_Browser -- "7 On App1's /profile page, JavaScript calls <br> App1's /api/data endpoint (e.g., GET) <br> (includes Access Token from session as Bearer token)" --> App1

    App1 -- "8 App1's /api/data endpoint receives request. <br> Triggers 'get_current_api_user' dependency." --> App1_Step9["App1: Validate Access Token <br> (KeycloakTokenValidator)"]
  
    App1_Step9 -- "9 Fetch JWKS from Keycloak to verify token signature <br> (backend call to internal jwks_uri specified in KeycloakTokenValidator, <br> which internally discovers it from Keycloak's internal .well-known)" --> Keycloak
    Keycloak -- "9a JWKS (Public Keys)" --> App1_Step9

    App1_Step9 -- "10 Verify Access Token: <br> - Signature (using JWKS) <br> - Issuer (vs public OIDC_ISSUER_URL) <br> - Audience (vs configured allowed_audiences + client_id) <br> - Expiry" --> App1_Step11{"App1: Token Validated"}
  
    App1_Step11 -- "11 If valid, extract user info (e.g., preferred_username) <br> and roles (e.g., realm_access.roles) from token claims" --> App1_Step12{"App1: Perform Casbin Authorization"}
  
    App1_Step12 -- "12 Load Casbin Model & Policy <br> (from local casbin_model.conf & casbin_policy.csv)" --> CasbinFiles
    App1_Step12 -- "13 Enforce Casbin policy <br> e.g., enforcer.enforce(username, '/api/data', 'GET')" --> App1_Step13{"App1: Casbin Authorization Decision"}
  
    App1_Step13 -- "14a If Authorized (policy allows): <br> Proceed to API logic, access/prepare data" --> App1_Step14a{"App1: Serve API Data"}
    App1_Step14a -- "15a Sends HTTP 200 OK with data <br> back to JavaScript on /profile page" --> User_Browser
  
    App1_Step13 -- "14b If Denied (policy disallows): <br> Prepare error response" --> App1_Step14b{"App1: Serve HTTP 403 Forbidden"}
    App1_Step14b -- "15b Sends HTTP 403 Forbidden <br> back to JavaScript on /profile page" --> User_Browser

    %% App2 - OIDC Login Flow (Simplified for SSO demonstration)
    User_Browser -- "A Accesses App2, Clicks Login <br> (Demonstrates SSO if already authenticated with Keycloak)" --> App2
    App2 -- "B User Agent redirected to Keycloak (if not already SSO'd)" --> User_Browser
    Keycloak -- "C Keycloak redirects User Agent to App2's /auth/callback <br> with Authorization Code" --> User_Browser
    App2 -- "D App2 (backend) exchanges Auth Code for Tokens" --> Keycloak
    App2 -- "E App2 serves content/profile" --> User_Browser

    %% Styling
    classDef app fill:#D6EAF8,stroke:#3498DB,stroke-width:2px;
    classDef idp fill:#D5F5E3,stroke:#2ECC71,stroke-width:2px;
    classDef user fill:#FDEDEC,stroke:#E74C3C,stroke-width:2px;
    classDef resource fill:#FEF9E7,stroke:#F1C40F,stroke-width:1px,stroke-dasharray: 2 2;
    classDef internalstep fill:#E8DAEF,stroke:#8E44AD,stroke-width:1px;
  
    class User_Browser user;
    class App1,App2 app;
    class Keycloak idp;
    class CasbinFiles resource;
    class App1_Step9, App1_Step11,App1_Step12,App1_Step13,App1_Step14a,App1_Step14binternalstep;
```

**UI User - Authentication (Keycloak) & API Access with Authorization (Casbin)**

```mermaid
graph LR
    %% Nodes
    UI_User[UI User]:::user
    Client_App["Client App (UI)"]:::component
    Keycloak["Keycloak (IdP)"]:::component
    API_Gateway[API Gateway]:::component
    Backend_Service["Backend Service<br>(e.g. Project Service)"]:::component
    Casbin_Enforcer[Casbin Enforcer]:::component

    %% Edges for Login Flow
    UI_User -->|1 Initiates Login| Client_App
    Client_App -->|"2 Redirect to /authorize<br>(OAuth2 Auth Code + PKCE)"| Keycloak
    Keycloak -->|3 Displays Login & Consent Page| UI_User
    UI_User -->|4 Submits Credentials & Grants Consent| Keycloak
    Keycloak -->|5 Redirect with Authorization Code| Client_App
    Client_App -->|"6 Exchanges Auth Code for Tokens<br>(ID, Access, Refresh) at /token"| Keycloak
    Keycloak -->|"7 {Access Token, ID Token, Refresh Token}"| Client_App

    %% Edges for API Call Flow
    Client_App -->|"8 API Request<br>(e.g., GET /projects) with Access Token"| API_Gateway
    API_Gateway -->|"9 Validate Access Token<br>(signature expiry with JWKS)"| API_Gateway
    API_Gateway -->|"10 Forward Request<br>+ User Info (from Token)"| Backend_Service
    Backend_Service -->|"11 Check Permission<br>(user_id, resource, action)"| Casbin_Enforcer
    Casbin_Enforcer -->|"12 Evaluate Policies<br>(e.g., from Policy DB)"| Casbin_Enforcer
    Casbin_Enforcer -->|"13 Authorization Decision<br>(Allow/Deny)"| Backend_Service
    Backend_Service -->|"14 API Response (if Allowed)<br>or HTTP 403 (if Denied)"| API_Gateway
    API_Gateway -->|15 API Response| Client_App

    %% Styling
    classDef user fill:#90EE90,stroke:#333,stroke-width:2px;
    classDef component fill:#ADD8E6,stroke:#333,stroke-width:2px;
```

**Explanation of Diagram :**

1. **Authentication with Keycloak:**
   * The UI User initiates login via the Client App.
   * The Client App redirects the user to Keycloak, using the OAuth 2.0 Authorization Code Grant with PKCE. ^^
   * The user authenticates with Keycloak and grants consent.
   * Keycloak issues an Authorization Code back to the Client App.
   * The Client App exchanges this code for an Access Token, ID Token, and Refresh Token from Keycloak's token endpoint. ^^
2. **API Access & Authorization with Casbin:**
   * The Client App makes an API request to a Backend Service (via an API Gateway), including the Keycloak-issued Access Token.
   * The API Gateway (or the Backend Service itself) validates the Access Token.
   * The Backend Service extracts user information (e.g., user ID or roles) from the validated token.
   * The Backend Service then calls the Casbin Enforcer, providing the user's identity, the resource they are trying to access, and the action they are attempting. ^^
   * Casbin evaluates this request against its configured policies (which could be stored in a database or file). ^^
   * Based on the policy evaluation, Casbin returns an "Allow" or "Deny" decision.
   * The Backend Service proceeds with the request if allowed or returns an error (e.g., HTTP 403 Forbidden) if denied.

```mermaid
graph LR
    %% Nodes
    SDK_CLI_User:::user
    Client_App_SDK:::component
    Keycloak["Keycloak (IdP)"]:::component
    API_Gateway[API Gateway]:::component
    Backend_Service_Doc:::component
    Casbin_Enforcer[Casbin Enforcer]:::component

    %% Edges for Login Flow (Device Authorization Grant)
    SDK_CLI_User -->|1 Initiates Login command| Client_App_SDK
    Client_App_SDK -->|"2 Request Device & User Codes<br>(OAuth2 Device Auth Grant)"| Keycloak
    Keycloak -->|"3 Returns {device_code, user_code, verification_uri}"| Client_App_SDK
    Client_App_SDK -->|4 Display user_code & verification_uri| SDK_CLI_User
    SDK_CLI_User -->|"5 Authenticates & Enters user_code<br>at verification_uri (on separate device)"| Keycloak
    Keycloak -->|"6 Authorization Successful (on separate device)"| SDK_CLI_User
    Client_App_SDK -->|"7 Polls /token endpoint with device_code"| Keycloak
    Keycloak -->|"8 Returns {Access Token, ID Token, Refresh Token}<br>(after user authorization & successful polling)"| Client_App_SDK

    %% Edges for API Call Flow
    Client_App_SDK -->|"9 API Request<br>(e.g., POST /documents) with Access Token"| API_Gateway
    API_Gateway -->|"10 Validate Access Token<br>(signature, expiry with JWKS)"| API_Gateway
    API_Gateway -->|"11 Forward Request<br>+ User Info (from Token)"| Backend_Service_Doc
    Backend_Service_Doc -->|"12 Check Permission<br>(user_id, resource, action)"| Casbin_Enforcer
    Casbin_Enforcer -->|"13 Evaluate Policies<br>(e.g., from Policy DB)"| Casbin_Enforcer
    Casbin_Enforcer -->|"14 Authorization Decision<br>(Allow/Deny)"| Backend_Service_Doc
    Backend_Service_Doc -->|"15 API Response (if Allowed)<br>or HTTP 403 (if Denied)"| API_Gateway
    API_Gateway -->|16 API Response| Client_App_SDK

    %% Styling
    classDef user fill:#90EE90,stroke:#333,stroke-width:2px;
    classDef component fill:#ADD8E6,stroke:#333,stroke-width:2px;
```

**Explanation of Diagram :**

1. **Authentication with Keycloak (Device Flow):**
   * The SDK/CLI User initiates a login command.
   * The Client App (SDK/CLI) requests device and user codes from Keycloak using the OAuth 2.0 Device Authorization Grant. ^^
   * Keycloak returns these codes, and the Client App displays the `user_code` and `verification_uri` to the user.
   * The user goes to the `verification_uri` on a separate device (e.g., a browser on a smartphone or computer), authenticates with Keycloak, and enters the `user_code`.
   * Meanwhile, the Client App (SDK/CLI) polls Keycloak's token endpoint with the `device_code`.
   * Once the user completes authorization on the separate device, Keycloak provides the Access Token, ID Token, and Refresh Token to the polling Client App. ^^
2. **API Access & Authorization with Casbin:**
   * This part is identical to the UI user flow. The Client App (SDK/CLI) uses the Keycloak-issued Access Token to make API requests.
   * The Backend Service, upon receiving the request (typically after token validation by an API Gateway or itself), uses Casbin to enforce authorization policies based on the user's identity (from the token), the requested resource, and the action
   * 

```mermaid
sequenceDiagram
    actor User_Browser
    participant App1_FastAPI as FastAPI App 1 (Host:8091)
    participant App2_FastAPI as FastAPI App 2 (Host:8092)
    participant Keycloak_Server as Keycloak (Host:8080)

    %% --- Login with App 1 ---
    User_Browser->>App1_FastAPI: 1. GET / (Access App 1)
    App1_FastAPI-->>User_Browser: 2. HTML (Index page with Login link)

    User_Browser->>App1_FastAPI: 3. GET /login (User clicks Login)
    activate App1_FastAPI
    App1_FastAPI-->>User_Browser: 4. HTTP 302 Redirect to Keycloak<br>(Location: Keycloak Auth URL with client_id=app1-fastapi-client, redirect_uri=http://localhost:8091/auth/callback)
    deactivate App1_FastAPI

    User_Browser->>Keycloak_Server: 5. GET /realms/poc-realm/protocol/openid-connect/auth?... (Follows redirect)
    activate Keycloak_Server
    Keycloak_Server-->>User_Browser: 6. HTML (Keycloak Login Page)
    User_Browser->>Keycloak_Server: 7. POST Credentials (user: testuser)
    Keycloak_Server-->>User_Browser: 8. HTTP 302 Redirect to App 1 Callback<br>(Location: http://localhost:8091/auth/callback?code=AUTH_CODE&state=...)
    deactivate Keycloak_Server

    User_Browser->>App1_FastAPI: 9. GET /auth/callback?code=AUTH_CODE&state=... (Follows redirect)
    activate App1_FastAPI
    Note over App1_FastAPI, Keycloak_Server: App 1 backend communicates with Keycloak backend<br>over Docker internal network (keycloak:8080)
    App1_FastAPI->>Keycloak_Server: 10. POST /realms/poc-realm/protocol/openid-connect/token<br>(Exchange AUTH_CODE for tokens: client_id, client_secret, code)
    activate Keycloak_Server
    Keycloak_Server-->>App1_FastAPI: 11. JSON {Access Token, ID Token, Refresh Token}
    deactivate Keycloak_Server
    App1_FastAPI-->>User_Browser: 12. HTTP 302 Redirect to /profile (Sets session cookie with user info)
    deactivate App1_FastAPI

    User_Browser->>App1_FastAPI: 13. GET /profile (Access protected page)
    App1_FastAPI-->>User_Browser: 14. HTML (App 1 Profile Page with user details)

    %% --- SSO with App 2 ---
    User_Browser->>App2_FastAPI: 15. GET / (Access App 2)
    App2_FastAPI-->>User_Browser: 16. HTML (Index page with Login link)

    User_Browser->>App2_FastAPI: 17. GET /login (User clicks Login on App 2)
    activate App2_FastAPI
    App2_FastAPI-->>User_Browser: 18. HTTP 302 Redirect to Keycloak<br>(Location: Keycloak Auth URL with client_id=app2-fastapi-client, redirect_uri=http://localhost:8092/auth/callback)
    deactivate App2_FastAPI

    User_Browser->>Keycloak_Server: 19. GET /realms/poc-realm/protocol/openid-connect/auth?... (Follows redirect)
    activate Keycloak_Server
    Note over Keycloak_Server: Keycloak recognizes existing SSO session for 'testuser'.<br>No re-authentication needed.
    Keycloak_Server-->>User_Browser: 20. HTTP 302 Redirect to App 2 Callback<br>(Location: http://localhost:8092/auth/callback?code=NEW_AUTH_CODE&state=...)
    deactivate Keycloak_Server

    User_Browser->>App2_FastAPI: 21. GET /auth/callback?code=NEW_AUTH_CODE&state=... (Follows redirect)
    activate App2_FastAPI
    Note over App2_FastAPI, Keycloak_Server: App 2 backend communicates with Keycloak backend<br>over Docker internal network (keycloak:8080)
    App2_FastAPI->>Keycloak_Server: 22. POST /realms/poc-realm/protocol/openid-connect/token<br>(Exchange NEW_AUTH_CODE for tokens)
    activate Keycloak_Server
    Keycloak_Server-->>App2_FastAPI: 23. JSON {Access Token, ID Token, Refresh Token}
    deactivate Keycloak_Server
    App2_FastAPI-->>User_Browser: 24. HTTP 302 Redirect to /profile (Sets session cookie with user info)
    deactivate App2_FastAPI

    User_Browser->>App2_FastAPI: 25. GET /profile (Access protected page)
    App2_FastAPI-->>User_Browser: 26. HTML (App 2 Profile Page with user details - SSO successful)

    %% --- API Demo Script (Conceptual) ---
    participant APIDemoScript as "keycloak_api_demo.py"
    Note right of Keycloak_Server: The keycloak_api_demo.py script<br>interacts directly with Keycloak's Admin API<br> (e.g., APIDemoScript -> Keycloak_Server : List Users)
```

# Keycloak and FastAPI Authentication PoC

This Proof of Concept demonstrates Keycloak's authentication capabilities with two simple FastAPI web applications, showcasing Single Sign-On (SSO), standard OIDC protocol usage, and a glimpse into Keycloak's admin features and API-driven nature.

Realm and client configuration are now automated via realm import.

## Features Demonstrated

1. **Single Sign-On (SSO):** Login to App1, and you'll be automatically logged into App2.
2. **User Federation (Conceptual):** Users are created in Keycloak. The Admin Console will show where LDAP/AD federation is configured.
3. **Standard Protocols (OIDC):** FastAPI apps use OpenID Connect.
4. **Admin Console & Account Management Console:** Accessible for Keycloak management and user self-service.
5. **API-Driven (Basic Example):** A Python script (`keycloak_api_demo/demo.py`) shows how to interact with Keycloak's Admin API.

## Prerequisites

* Docker Desktop installed and running.
* Git (to clone this repository, or just create the files manually).

## Setup and Running

### 1. Prepare the Environment

* Create the folder structure and files as described.
* Open a terminal in the `keycloak-fastapi-poc` directory.

Aspect `app1``app2`**Role**OIDC Client, API Resource ServerOIDC Client (primarily for SSO demo) **Protected API (self-hosted)** Yes (`/api/data`)No**API Token Validation**Yes (custom `KeycloakTokenValidator`)Not Applicable**Authorization**Yes (Casbin)No**OIDC Scopes** `openid email profile roles``openid email profile`**Key Feature Demonstrated**Protecting custom APIs with Keycloak tokens & fine-grained AuthZ (Casbin)Basic OIDC login and SSO with another app**Complexity**HigherLower**OIDC Config Strategy**Manual `server_metadata` + explicit endpoint URLs (after debugging)Manual `server_metadata` + explicit endpoint URLs (modeled after `app1`)

### 2. Keycloak Configuration (Manual Steps after Keycloak starts)

First, start Keycloak to perform these steps:

### 3. App1 & App2 comparision summary

`app1` has an additional dependency on `casbin` due to its authorization feature.

`app2` has a slightly simpler set of dependencies, lacking `casbin`

| Aspect                      | app1                                                                      | app2                                                                 |
| --------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Role                        | OIDC Client, API Resource Server                                          | OIDC Client (primarily for SSO demo)                                 |
| Protected API (self-hosted) | Yes (/api/data)                                                           | No                                                                   |
| API Token Validation        | Yes (custom KeycloakTokenValidator)                                       | Not Applicable                                                       |
| Authorization               | Yes (Casbin)                                                              | No                                                                   |
| OIDC Scopes                 | openid email profile roles                                                | openid email profile                                                 |
| Key Feature Demonstrated    | Protecting custom APIs with Keycloak tokens & fine-grained AuthZ (Casbin) | Basic OIDC login and SSO with another app                            |
| Complexity                  | Higher                                                                    | Lower                                                                |
| OIDC Config Strategy        | Manual server_metadata + explicit endpoint URLs (after debugging)         | Manual server_metadata + explicit endpoint URLs (modeled after app1) |

### 4. Tests

* **Login** :
* Navigate to `http://localhost:8092`
* Click login. You should be redirected to Keycloak.
* Log in with `testuser/password`.
* You should be redirected back to `app2`'s profile page, displaying user information. (This you've confirmed works).
* **Profile Page** :
* Verify that the user information displayed (name, email, etc.) is correct for `testuser`.
* **Logout** :
* From the profile page (or homepage if logged in), click logout.
* You should be redirected to Keycloak for logout, and then Keycloak should redirect you back to `app2`'s homepage (`http://localhost:8092/`).
* Verify that you are indeed logged out of `app2` (e.g., the homepage shows "You are not logged in").
* **Single Sign-On (SSO) with `app1`** :
* **Scenario 1: Login to `app1` first, then `app2`**

  1. Ensure you are fully logged out of both apps and Keycloak (clear browser history/cookies for `localhost` or use an incognito window for a clean test).
  2. Go to `app1` http://localhost:8091/ (`http://localhost:8091/`) and log in with `testuser/password`.
  3. Now, in the  *same browser session* , open a new tab and navigate to `app2` (`http://localhost:8092/`).
  4. When you click "Login" on `app2`, you should ideally be logged in *without* needing to re-enter credentials at Keycloak, or Keycloak might briefly appear and redirect you back quickly. You should land on `app2`'s profile page. This demonstrates SSO.
* **Scenario 2: Login to `app2` first, then `app1`**

  1. Ensure clean browser state.
  2. Go to `app2` (`http://localhost:8092/`) and log in.
  3. In the same browser session, navigate to `app1` (`http://localhost:8091/`).
  4. Click "Login" on `app1`. You should experience SSO and be logged into `app1`'s profile page.
* **Single Logout (SLO) - (Basic Check)** :
* Log in to both `app1` and `app2` in the same browser.
* Log out from `app1`.
* Now, go to `app2`. Are you still logged into `app2`, or are you logged out?
* Then try logging out from `app2` and check `app1`.
* *Note* : True OIDC front-channel or back-channel logout for full SLO across multiple applications can be complex to configure perfectly and might require more settings in Keycloak clients (like Front-channel logout URLs) and specific handling in the apps. Your current setup does a standard OIDC logout which logs the user out of Keycloak and the current app. The SSO session at Keycloak being terminated should mean other apps will require re-authentication.

#### Authorization Test

testuser:

In Keycloak, under your poc-realm, go to "Realm Roles".

Create a new role named data_readers_role.
Go to "Users", select testuser.
Go to the "Role mapping" tab for testuser.
Assign the data_readers_role to testuser from "Available Roles" to "Assigned Roles".

"Admin" User (e.g., create adminuser):
In Keycloak, create a new user, for example:
Username: adminuser
Set a password (e.g., password).
Ensure "Email verified" is on if needed by your setup.
Create a realm role named admin_role (if it doesn't exist).
Assign the admin_role to your adminuser.

"Regular" User (e.g., create nouser with no specific API roles):
In Keycloak, create another user:
Username: nouser
Set a password (e.g., password).
Do not assign admin_role or data_readers_role to this user.

Scenario 1: testuser
testuser has direct GET permission and GET permission via data_readers_role.testuser should NOT have POST permission.
Get Access Token for testuser -- login to app1 .. inspect get value of fullaccesstoken

Test GET /api/data (Expected: ALLOWED):

ACCESS_TOKEN_TESTUSER="eyJhbGciOiJSUzI1NiIsInR5cCIgOiA"
$ curl -X GET http://localhost:8091/api/data -H "Authorization: Bearer $ACCESS_TOKEN_TESTUSER"
[{"id":"item1","name":"Sample Item Alpha","value":"This is a test item."},{"id":"item2","name":"Sample Item Beta","value":"Another piece of data."}]

curl -X POST http://localhost:8091/api/data 
    -H "Authorization: Bearer $ACCESS_TOKEN_TESTUSER"
    -H "Content-Type: application/json"
    -d '{"id": "item_test", "name": "Test Item by testuser", "value": "some value"}'

$ curl -X POST http://localhost:8091/api/data \

> -H "Authorization: Bearer $ACCESS_TOKEN_TESTUSER" 
> -H "Content-Type: application/json" 
> -d '{"id": "item_test", "name": "Test Item by testuser", "value": "some value"}'
> {"detail":"Not authorized to POST data"}

Scenario 2: adminuser (with admin_role)
adminuser (via admin_role) should have GET and POST permission.
Get Access Token for adminuser.

Test GET /api/data (Expected: ALLOWED):

**GET**

ACCESS_TOKEN_ADMINUSER="eyJhbGciOiJSUzI1NiIsInR5cg"
curl -X GET http://localhost:8091/api/data -H "Authorization: Bearer $ACCESS_TOKEN_ADMINUSER"

**POST**

curl -X POST http://localhost:8091/api/data 
    -H "Authorization: Bearer $ACCESS_TOKEN_ADMINUSER"
    -H "Content-Type: application/json"
    -d '{"id": "item_admin", "name": "Admin Item", "value": "posted by admin"}'

result
{"id":"item_admin","name":"Admin Item","value":"posted by admin"}

Scenario 3: nouser (no specific relevant roles)
nouser should have NEITHER GET nor POST permission.

**GET**

ACCESS_TOKEN_NOUSER="eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICItYkR2bGF"
curl -X GET http://localhost:8091/api/data -H "Authorization: Bearer $ACCESS_TOKEN_NOUSER"

{"detail":"Not authorized to GET data"}

**POST**

curl -X POST http://localhost:8091/api/data 
    -H "Authorization: Bearer $ACCESS_TOKEN_NOUSER"
    -H "Content-Type: application/json"
    -d '{"id": "item_nouser", "name": "NoUser Item", "value": "attempted by nouser"}'

{"detail":"Not authorized to POST data"}
