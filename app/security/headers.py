from flask import request

CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "        # data: nécessaire pour le QR code MFA
    "style-src 'self'; "
    "script-src 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "base-uri 'self'"
)


def init_app(app):
    @app.after_request
    def set_security_headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=()")
        # HSTS n'a de sens qu'en HTTPS
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains")
        # Pas de cache pour les pages dynamiques (retour arrière après logout)
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp