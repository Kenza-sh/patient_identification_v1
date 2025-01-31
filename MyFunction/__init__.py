import azure.functions as func
import logging
import re
import json
from typing import Optional, Dict


class InformationExtractor:
    def __init__(self):
        # Initialisation unique du modèle NER
        logger.info("Initialisation du modèle NER...")
       
        logger.info("Modèle NER initialisé avec succès.")
    
    def extraire_numero_telephone(self, texte):
        logger.info(f"Extraction du numéro de téléphone à partir du texte : {texte}")
        # Normalisation du texte en supprimant les espaces, tirets, et points
        phone_number = texte.replace(" ", "").replace("-", "").replace(".", "")

        # Premier regex : validation des numéros compactés
        phone_regex = r"^(\+?\d{1,3})?(\d{9,10})$"
        numero_telephone = re.search(phone_regex, phone_number)

        if numero_telephone:
            logger.info(f"Numéro de téléphone extrait : {numero_telephone.group()}")
            return numero_telephone.group()

        # Deuxième regex : validation des formats avec séparateurs (espaces, tirets)
        numero_telephone = re.search(r"(\+?\d{1,3}[\s-]?)?(\(?\d{1,4}\)?[\s-]?)?(\d{2}[\s-]?){4}\d{2}", phone_number)

        if numero_telephone:
            logger.info(f"Numéro de téléphone extrait avec séparateurs : {numero_telephone.group()}")
            return numero_telephone.group()

        logger.warning("Aucun numéro de téléphone valide n'a été extrait.")
        return None

    def extraire_code_postal(self, texte):
        logger.info(f"Extraction du code postal à partir du texte : {texte}")
        code_postal = re.search(r"\b\d{5}\b", texte)
        if code_postal:
            logger.info(f"Code postal extrait : {code_postal.group()}")
            return code_postal.group()
        else:
            logger.warning("Aucun code postal valide n'a été extrait.")
        return None

    def extraire_adresse_mail(self, texte):
        logger.info(f"Extraction de l'adresse email à partir du texte : {texte}")
        texte = re.sub(r'\s*arobase\s*', '@', texte, flags=re.IGNORECASE)
        adresse_mail = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", texte)

        if adresse_mail:
            logger.info(f"Adresse email extraite : {adresse_mail[0].strip()}")
            return adresse_mail[0].strip()
        else:
            logger.warning("Aucune adresse email valide n'a été extraite.")
        return None

extractor = InformationExtractor()

# Dictionnaire des actions disponibles
handlers: Dict[str, callable] = {
    "extraire_adresse_mail": extractor.extraire_adresse_mail,
    "extraire_code_postal": extractor.extraire_code_postal,
    "extraire_numero_telephone": extractor.extraire_numero_telephone
}

def main(req: func.HttpRequest) -> func.HttpResponse:
    """Gère la requête en fonction de l'action demandée"""
    logger.info("Début du traitement de la requête HTTP")

    try:
        req_body = req.get_json()
        logger.info("Corps de la requête JSON récupéré avec succès")
    except ValueError as e:
        logger.error(f"Erreur lors du traitement de la requête : {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON format"}),
            mimetype="application/json",
            status_code=400
        )

    # Extraction et validation des paramètres
    action = req_body.get("action", "").strip()
    texte = req_body.get("texte", "").strip()

    if not action or not texte:
        return func.HttpResponse(
            json.dumps({"error": "Paramètres 'action' et 'texte' requis"}),
            mimetype="application/json",
            status_code=400
        )

    logger.info(f"Action reçue : {action}")
    logger.info(f"Texte reçu : {texte[:50]}...")  # Limite pour éviter d'exposer des données sensibles

    # Vérification si l'action est valide
    handler = handlers.get(action)
    if not handler:
        logger.error(f"Action inconnue : {action}")
        return func.HttpResponse(
            json.dumps({"error": "Action inconnue"}),
            mimetype="application/json",
            status_code=400
        )

    logger.info(f"Exécution de l'action : {action}")

    # Exécuter la fonction correspondante et retourner le résultat
    try:
        result = handler(texte)
        return func.HttpResponse(
            json.dumps({"response": result}),
            mimetype="application/json",
            status_code=200
        )
    except Exception as e:
        logger.error(f"Erreur lors de l'exécution de l'action '{action}': {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Erreur lors de l'exécution: {str(e)}"}),
            mimetype="application/json",
            status_code=500
        )

           
