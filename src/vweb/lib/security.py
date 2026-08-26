"""Content Security Policy and Talisman configuration.

When adding new CDN sources, update the CSP dict here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flask_talisman import Talisman
from loguru import logger

if TYPE_CHECKING:
    from flask import Flask

    from vweb.config import Settings

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def configure_security(app: Flask, s: Settings) -> None:
    """Apply Flask-Talisman with the app's content security policy.

    Args:
        app: The Flask application instance.
        s: The application settings.
    """
    if s.force_https and s.host in _LOOPBACK_HOSTS:
        logger.warning(
            "force_https is enabled while host is {!r} (loopback). Requests will be "
            "redirected to https://{}:{}, which has no TLS listener here and will "
            "hang or fail to connect. This is almost always a local-dev "
            "misconfiguration — set VWEB_ENV=development or VWEB_FORCE_HTTPS=false.",
            s.host,
            s.host,
            s.port,
        )

    script_src = [
        "'self'",
        "'unsafe-eval'",
        "unpkg.com",
        "cdn.jsdelivr.net",
        "kit.fontawesome.com",
        "ka-f.fontawesome.com",
    ]

    csp = {
        "default-src": "'self'",
        "script-src": script_src,
        "style-src": [
            "'self'",
            "'unsafe-inline'",
            "cdn.jsdelivr.net",
            "ka-f.fontawesome.com",
            "fonts.googleapis.com",
        ],
        "font-src": [
            "'self'",
            "ka-f.fontawesome.com",
            "fonts.gstatic.com",
        ],
        "img-src": [
            "'self'",
            "data:",
            "cdn.discordapp.com",
            "cdn.valentina-noir.com",
            "avatars.githubusercontent.com",
            "lh3.googleusercontent.com",
            "img.daisyui.com",
            "cdn.midjourney.com",
            "picsum.photos",
            "fastly.picsum.photos",
        ],
        "connect-src": [
            "'self'",
            "ka-f.fontawesome.com",
        ],
    }
    Talisman(
        app,
        force_https=s.force_https,
        session_cookie_secure=s.force_https,
        session_cookie_http_only=True,
        # Sign in with Apple returns via a cross-site form_post. A "Lax" cookie is
        # not sent on a cross-site POST, which would drop the OAuth state and break
        # the callback, so the session cookie must be "None". That requires Secure,
        # which force_https guarantees; CSRF stays protected by flask-wtf tokens.
        # Locally (no HTTPS) browsers reject SameSite=None, and Apple cannot reach
        # localhost anyway, so keep "Lax" there.
        session_cookie_samesite="None" if s.force_https else "Lax",
        content_security_policy=csp,
    )
