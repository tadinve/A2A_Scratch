"""Days 07-08: operator-only enrollment. Verify a Google account and, after you
confirm it, link its `sub` to an internal user in Firestore. Mints NO application token.

    # stop the Identity Service first: this listens on its callback URI (localhost:8002)
    uv run python scripts/google_enroll.py                  # show the verified identity only
    uv run python scripts/google_enroll.py --link user-001  # ...then link it, after you type "yes"

It runs its own full Google flow (state, nonce, PKCE S256) and verifies the ID token
exactly as the Identity Service does. The verified subject and email appear in THIS
terminal only (the browser page shows neither). The user must already exist and be
enabled (scripts/identity_users.py add user-001). A Google account, or a user, that
already has a link is refused: links are never silently replaced.
"""

import argparse
import getpass
import http.server
import secrets
import sys
import threading
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(Path(__file__).resolve().parent.parent / "identity_service" / ".env")

from identity_service.datastore import StoreUnavailable, build_stores  # noqa: E402
from identity_service.external_identities import LinkConflict  # noqa: E402
from identity_service.google_oidc import GoogleError, GoogleOIDC, load_google_settings  # noqa: E402
from identity_service.users import check_user_id  # noqa: E402

WAIT_SECONDS = 300


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a Google account; optionally link it to a user.")
    parser.add_argument("--link", metavar="USER_ID", help="link the verified account to this internal user")
    args = parser.parse_args()
    stores = None
    try:
        if args.link:
            check_user_id(args.link)
            stores = build_stores()
            if stores.backend != "firestore":
                print("refusing to link in the memory store: nothing would persist", file=sys.stderr)
                return 2
            if not stores.users.is_enabled(args.link):
                print(f"{args.link} does not exist or is disabled: "
                      f"run scripts/identity_users.py add {args.link} first", file=sys.stderr)
                return 1
        settings = load_google_settings()
    except (RuntimeError, ValueError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except StoreUnavailable as exc:
        print(f"Firestore unavailable ({exc.operation})", file=sys.stderr)
        return 1
    if settings is None:
        print("Google sign-in is not configured: fill in identity_service/.env first", file=sys.stderr)
        return 2
    redirect = urlsplit(settings.redirect_uri)
    if redirect.scheme != "http" or redirect.hostname != "localhost":
        print("enrollment runs only against a http://localhost redirect URI", file=sys.stderr)
        return 2

    oidc = GoogleOIDC(settings)
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    result: dict = {}
    done = threading.Event()

    class Callback(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlsplit(self.path)
            if url.path != redirect.path:
                self.send_error(404)
                return
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            if not secrets.compare_digest(q.get("state", ""), state):
                result["error"] = "state mismatch"
            elif "error" in q:
                result["error"] = f"Google returned error={q['error']}"
            elif not q.get("code"):
                result["error"] = "no authorization code"
            else:
                try:
                    result["identity"] = oidc.complete(q["code"], verifier, nonce)
                except GoogleError as exc:
                    result["error"] = f"{type(exc).__name__} at {exc.stage}"
            body = b"Enrollment step finished. Return to the terminal.\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)
            done.set()

        def log_message(self, *args):       # the default logs the query string: it holds the code
            pass

    try:
        server = http.server.HTTPServer(("127.0.0.1", redirect.port or 80), Callback)
    except OSError as exc:
        print(f"cannot listen on port {redirect.port}: {exc.strerror}. Stop the Identity Service first.",
              file=sys.stderr)
        return 1
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        auth_url = oidc.authorization_url(state, nonce, verifier)
    except GoogleError as exc:
        server.shutdown()
        print(f"Google unavailable ({exc.stage})", file=sys.stderr)
        return 1
    print("Opening Google sign-in. Choose the account that will represent Alice.")
    print(f"If no browser opens, visit:\n  {auth_url}\n")
    webbrowser.open(auth_url)

    finished = done.wait(WAIT_SECONDS)
    server.shutdown()
    if not finished:
        print("timed out waiting for the Google callback", file=sys.stderr)
        return 1
    if "error" in result:
        print(f"not enrolled: {result['error']}", file=sys.stderr)
        return 1
    identity = result["identity"]
    print("Verified Google identity (no application token was issued):")
    print(f"  issuer : {identity.issuer}")
    print(f"  subject: {identity.subject}")
    print(f"  email  : {identity.email}  (shown for confirmation only; never used for linking)")
    if not args.link:
        print("\nTo link it: rerun with --link USER_ID")
        return 0
    answer = input(f"\nLink THIS Google account to {args.link}? Type yes to confirm: ")
    if answer.strip() != "yes":
        print("not linked")
        return 1
    try:
        stores.links.link(identity.issuer, identity.subject, args.link, linked_by=getpass.getuser())
    except LinkConflict as exc:
        print(f"not linked: {exc}", file=sys.stderr)
        return 1
    except StoreUnavailable as exc:
        print(f"not linked: Firestore unavailable ({exc.operation})", file=sys.stderr)
        return 1
    print(f"linked ({identity.issuer}, {identity.subject}) -> {args.link} in {stores.description}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
