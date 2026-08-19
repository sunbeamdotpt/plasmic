# auth

Plasmic authentication uses [Passport](https://www.passportjs.org/) to handle
multiple strategies for signing in, such as password, Google, Okta, etc.

## Google

To set up Google sign-in for local development, follow these instructions:

1. Sign in to https://console.cloud.google.com/.
2. Create a separate project for Plasmic development.
3. Go to the Credentials page and create a new "Oauth client ID".
4. Fill in the following fields:
   - Application type: Web application
   - Name: App name, e.g. "Plasmic Dev (my_username)"
   - Authorized JavaScript origins: http://localhost:3003
   - Authorized redirect URIs: http://localhost:3003/api/v1/oauth2/google/callback
5. Copy the "Client ID" and "Client secret", and paste them into your
   secrets.json file ([docs about secrets](/platform/wab/src/wab/server/secrets.ts).
   ```json
   {
     "google": {
       "clientId": "copy from Google",
       "clientSecret": "copy from Google"
     }
   }
   ```

Now go to http://localhost:3003/login and sign in with Google!

## Okta

We have a shared Okta dev instance at https://dev-2205008.okta.com/.

In Bitwarden, you'll find 3 accounts that you can use:

- Admin user: for configuring the Okta dev instance
- Test user: for manual testing and development
- Test user for CI/CD: for automated testing

To set up Okta SSO for local development, follow these instructions:

1. Go to the [Plasmic Generic SSO Test app](https://dev-2205008-admin.okta.com/admin/app/oidc_client/instance/0oa7xfuoxgo9Jsfu45d7/).
2. Sign in as the admin user (credentials in Bitwarden).
   You should see a client ID and client secret, which you'll need later.
3. Go to https://localhost:3003/admin/teams.
4. Lookup a team and open it.
5. Scroll down, open the "Misc" tab, and click "Configure SSO".
6. Fill in the following fields:
   - Domain: dev-2205008.okta.com
   - Provider: Okta
   - Config:
     ```json
     {
       "audience": "https://dev-2205008.okta.com",
       "clientID": "copy from Okta",
       "clientSecret": "copy from Okta"
     }
     ```
7. There should now be a new row in the `sso_config` table.
   Update the `tenantId` to `6RB4POx0y1gr7rCNvTDMMc`.

Now go to http://localhost:3003/sso and use the test user to sign in.

## OIDC (hosted / on-site deployments)

For forked on-site deployments, Plasmic can be configured to use a single,
global OIDC provider as the only sign-in method.

You can configure it either with environment variables or by adding an `oidc`
entry to your `~/.plasmic/secrets.json` file. Environment variables take
precedence over `secrets.json` values.

```bash
# Required
OIDC_AUTHORIZATION_URL=https://your-idp.example.com/oauth2/authorize
OIDC_TOKEN_URL=https://your-idp.example.com/oauth2/token
OIDC_USER_INFO_URL=https://your-idp.example.com/oauth2/userinfo
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret

# Optional
OIDC_ISSUER=https://your-idp.example.com
OIDC_CALLBACK_URL=https://your-plasmic.example.com/api/v1/auth/oidc/callback
OIDC_SCOPE="openid email profile"
OIDC_BUTTON_LABEL="Sign in with SSO"
OIDC_DISABLE_OTHER_AUTH=true
OIDC_ADMIN_EMAILS_BYPASS='["admin@example.com"]'
```

Equivalent `secrets.json` entry:

```json
{
  "oidc": {
    "clientId": "your-client-id",
    "clientSecret": "your-client-secret",
    "authorizationUrl": "https://your-idp.example.com/oauth2/authorize",
    "tokenUrl": "https://your-idp.example.com/oauth2/token",
    "userInfoUrl": "https://your-idp.example.com/oauth2/userinfo",
    "issuer": "https://your-idp.example.com",
    "callbackUrl": "https://your-plasmic.example.com/api/v1/auth/oidc/callback",
    "scope": "openid email profile",
    "buttonLabel": "Sign in with SSO",
    "disableOtherAuth": true,
    "adminEmailsBypass": ["admin@example.com"]
  }
}
```

When `OIDC_DISABLE_OTHER_AUTH` is `true` (the default when OIDC is configured),
the login and sign-up pages show only the OIDC button. Local/password and Google
sign-in are hidden, and the corresponding API endpoints reject non-admin
requests.

Users whose email is in `OIDC_ADMIN_EMAILS_BYPASS` (or `ADMIN_EMAILS` if the
bypass list is not set) can still sign in with the local/password flow. This is
intended for initial bootstrap and emergency recovery if OIDC is misconfigured.

First-time OIDC users are automatically created in the `User` table. OIDC tokens
are stored encrypted in the `OauthToken` table.
