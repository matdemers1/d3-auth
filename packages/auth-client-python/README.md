# d3auth-client

The relying-party half of D3 Auth for FastAPI and Starlette, over Authlib.

The ten rules of the consumer contract live in the provider's repo at
`docs/consumer-contract.md`. This package exists so the four easiest to get wrong come for free:
a pinned algorithm list, identity by `(iss, sub)`, roles refreshed on every renewal, and a
back-channel logout handler that is idempotent by `jti`.

```bash
pip install -e './packages/auth-client-python[fastapi]'
```

```python
from d3auth_client import BackchannelHandler, D3AuthClient, identity_key
from d3auth_client.fastapi import backchannel_router

auth = D3AuthClient(
    issuer="https://auth.d3cloud.io",
    client_id="your-app",
    client_secret=os.environ["CLIENT_SECRET"],
)

# Sign-in: Authlib keeps state, nonce and the PKCE verifier in the session.
await auth.begin_sign_in(request, redirect_uri="https://your-app.example/callback")

# Callback: the ID token is verified, and the roles come with it.
session = await auth.complete_sign_in(request)
account_key = identity_key(session.identity)   # never the email address

# Back-channel logout, mounted in one line.
handler = BackchannelHandler(
    issuer="https://auth.d3cloud.io",
    client_id="your-app",
    end_session=lambda logout: store.end_session(sid=logout.sid, sub=logout.sub),
)
app.include_router(backchannel_router(handler))
```

## Tests

```bash
python -m venv .venv && .venv/bin/pip install -e '.[fastapi,dev]'
.venv/bin/python -m pytest -q
```

CI runs them on every push; the image job will not publish without them.
