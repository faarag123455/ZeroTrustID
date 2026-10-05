import re

MIN_LENGTH = 12


def validate_password_policy(password):
    """Retourne la liste des erreurs (liste vide = mot de passe valide)."""
    errors = []
    if len(password) < MIN_LENGTH:
        errors.append(f"Au moins {MIN_LENGTH} caractères.")
    if not re.search(r"[a-z]", password):
        errors.append("Au moins une minuscule.")
    if not re.search(r"[A-Z]", password):
        errors.append("Au moins une majuscule.")
    if not re.search(r"\d", password):
        errors.append("Au moins un chiffre.")
    if not re.search(r"[^\w\s]", password):
        errors.append("Au moins un caractère spécial.")
    return errors