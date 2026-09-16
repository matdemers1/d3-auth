# Rule tests for .semgrep/d3auth.yml. Run: semgrep --test .semgrep/
from joserfc import jwt

token = ""
keys = None

# ruleid: d3auth.python-jwt-decode-without-algorithms
jwt.decode(token, keys)
# ok: d3auth.python-jwt-decode-without-algorithms
jwt.decode(token, keys, algorithms=["ES256", "RS256"])
