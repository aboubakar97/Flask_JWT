from flask import Flask, jsonify, request, render_template, redirect, url_for, make_response
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    jwt_required,
    JWTManager,
    verify_jwt_in_request,
    get_jwt,
    set_access_cookies,
    unset_jwt_cookies
)
from functools import wraps
from datetime import timedelta

app = Flask(__name__)

# Configuration JWT
app.config["JWT_SECRET_KEY"] = "Ma_clé_secrete"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)  # 1 heure
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]  # Stockage dans les cookies
app.config["JWT_COOKIE_SECURE"] = False  # À mettre en True en production (HTTPS)
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # Simplification pour l'exercice
jwt = JWTManager(app)

# Mock utilisateurs avec rôles
users = {
    "test": {"password": "test", "role": "user"},
    "admin": {"password": "admin", "role": "admin"}
}

# Décorateur pour vérifier le rôle admin
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims.get("role") != "admin":
                return render_template("error.html", message="Accès admin requis"), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

# Routes principales
@app.route('/')
def home():
    return render_template('formulaire.html')

@app.route('/formulaire.html')
def formulaire():
    return render_template('formulaire.html')

# Gestion du login via formulaire HTML
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    
    user = users.get(username)
    if not user or user["password"] != password:
        return render_template("error.html", message="Identifiants invalides"), 401

    # Création du token avec rôle
    access_token = create_access_token(
        identity=username,
        additional_claims={"role": user["role"]}
    )
    
    # Réponse avec cookie JWT
    resp = make_response(redirect(url_for("protected_page")))
    set_access_cookies(resp, access_token)
    return resp

# Route protégée avec JWT dans les cookies
@app.route("/protected")
@jwt_required()
def protected_page():
    current_user = get_jwt_identity()
    claims = get_jwt()
    return render_template(
        "protected.html",
        username=current_user,
        role=claims.get("role")
    )

# Route admin protégée
@app.route("/admin")
@admin_required()
def admin_dashboard():
    current_user = get_jwt_identity()
    return render_template("admin.html", username=current_user)

# Déconnexion (supprime les cookies)
@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("home")))
    unset_jwt_cookies(resp)
    return resp

if __name__ == "__main__":
    app.run(debug=True)
