from flask import Flask, jsonify, request, render_template
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    jwt_required,
    JWTManager,
    verify_jwt_in_request,
    get_jwt
)
from functools import wraps

app = Flask(__name__)

# Configuration JWT
app.config["JWT_SECRET_KEY"] = "Ma_clé_secrete"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 3600  # 1 heure
jwt = JWTManager(app)

# Mock utilisateurs avec rôles
users = {
    "test": {"password": "test", "role": "user"},
    "admin": {"password": "admin", "role": "admin"}  # Nouvel utilisateur admin
}

# Décorateur pour vérifier le rôle admin
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()  # Vérifie le JWT
            claims = get_jwt()      # Récupère les claims
            if claims.get("role") != "admin":
                return jsonify({"msg": "Accès refusé : Admin requis"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

@app.route('/')
def hello_world():
    return render_template('accueil.html')

# Route de login (avec gestion des rôles)
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    
    user = users.get(username)
    if not user or user["password"] != password:
        return jsonify({"msg": "Mauvais utilisateur ou mot de passe"}), 401

    # Crée le token avec le rôle dans les claims
    access_token = create_access_token(
        identity=username,
        additional_claims={"role": user["role"]}
    )
    return jsonify(access_token=access_token)

# Route protégée standard
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# Nouvelle route admin (protégée par rôle)
@app.route("/admin", methods=["GET"])
@admin_required()
def admin_dashboard():
    current_user = get_jwt_identity()
    return jsonify(msg=f"Bienvenue dans l'interface admin, {current_user} !"), 200

if __name__ == "__main__":
    app.run(debug=True)
