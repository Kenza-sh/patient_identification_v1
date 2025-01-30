import azure.functions as func
import logging
def install(package):
    # This function will install a package if it is not present
    from importlib import import_module
    try:
        import_module(package)
    except:
        from sys import executable as se
        from subprocess import check_call
        check_call([se,'-m','pip','-q','install',package])


for package in ['transformers']:
    install(package)
    
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
import re
import dateparser
import json
from typing import Optional, Dict

app =func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)
# Configuration du logger optimisée pour Azure Functions
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class InformationExtractor:
    def __init__(self):
        # Initialisation unique du modèle NER
        logger.info("Initialisation du modèle NER...")
        self.tokenizer = AutoTokenizer.from_pretrained("Jean-Baptiste/camembert-ner-with-dates")
        self.model = AutoModelForTokenClassification.from_pretrained("Jean-Baptiste/camembert-ner-with-dates")
        self.nlp = pipeline('ner', model=self.model, tokenizer=self.tokenizer, aggregation_strategy="simple")
        logger.info("Modèle NER initialisé avec succès.")

    def check_noun(self, msg_2_check):
        logger.debug(f"Vérification du nom : {msg_2_check}")
        def check_str(msg_2_check: str) -> bool:
            return isinstance(msg_2_check, str) and bool(msg_2_check.strip()) and any(ele in msg_2_check for ele in ["a", "e", "i", "o", "u", "y"])

        if not check_str(msg_2_check):
            logger.warning(f"Le message {msg_2_check} n'est pas une chaîne valide.")
            return False

        if not re.match(r"^[a-zA-ZÀ-ÿ' -]+$", msg_2_check):
            logger.warning(f"Le message {msg_2_check} contient des caractères invalides.")
            return False
        return True

    def extraire_nom(self, texte):
        logger.info(f"Extraction du nom à partir du texte : {texte}")
        entities = self.nlp(texte)
        for ent in entities:
            if ent['entity_group'] == "PER":
                if self.check_noun(ent['word'].lower()):
                    logger.info(f"Nom extrait : {ent['word'].upper()}")
                    return ent['word'].upper()
        logger.warning("Aucun nom n'a été extrait.")
        return None

    def extraire_prenom(self, texte):
        logger.info(f"Extraction du prénom à partir du texte : {texte}")
        entities = self.nlp(texte)
        for ent in entities:
            if ent['entity_group'] == "PER":
                if self.check_noun(ent['word']):
                    logger.info(f"Prénom extrait : {ent['word']}")
                    return ent['word'].upper()
        logger.warning("Aucun prénom n'a été extrait.")
        return None

    def extraire_date_naissance(self, texte):
        logger.info(f"Extraction de la date de naissance à partir du texte : {texte}")
        entities = self.nlp(texte)
        for ent in entities:
            if ent['entity_group'] == "DATE":
                date_str = ent['word']
                date_obj = dateparser.parse(date_str)
                if date_obj:
                    formatted_date = date_obj.strftime("%Y-%m-%d")
                    logger.info(f"Date de naissance extraite : {formatted_date}")
                    return formatted_date
                else:
                    logger.warning(f"Date non valide extraites : {date_str}")
                    return date_str
        logger.warning("Aucune date de naissance n'a été extraite.")
        return None

    def extraire_adresse(self, texte):
        logger.info(f"Extraction de l'adresse à partir du texte : {texte}")
        # Extraction du numéro de rue
        numero_rue = re.search(r'\b\d+\b', texte)
        adr = f"{numero_rue.group()} " if numero_rue else ""
        adr=''
        # Extraction des entités pertinentes
        entities = self.nlp(texte)
        for ent in entities:
            if ent['entity_group'] in {"LOC", "PER"}:
                adr += ent['word'] + ' '

        adr = adr.strip()
        if adr:
            logger.info(f"Adresse extraite : {adr}")
        else:
            logger.warning("Aucune adresse n'a été extraite.")
        return adr

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
    "extraire_nom": extractor.extraire_nom,
    "extraire_prenom": extractor.extraire_prenom,
    "extraire_date_naissance": extractor.extraire_date_naissance,
    "extraire_adresse": extractor.extraire_adresse,
    "extraire_adresse_mail": extractor.extraire_adresse_mail,
    "extraire_code_postal": extractor.extraire_code_postal,
    "extraire_numero_telephone": extractor.extraire_numero_telephone
}

@app.route(route="patient_ident")
def patient_ident(req: func.HttpRequest) -> func.HttpResponse:
    """Gère la requête en fonction de l'action demandée"""
    logger.info("Début du traitement de la requête HTTP")
    try:
        req_body = req.get_json()
        logger.info("Corps de la requête JSON récupéré avec succès")
    except ValueError:
        logger.error("Erreur lors de la récupération du corps de la requête. Le JSON est invalide.")
        return func.HttpResponse("Invalid JSON", status_code=400)

    action = req_body.get("action", "").strip()
    texte = req_body.get("texte", "").strip()

    # Vérification des paramètres
    if not action or not texte:
        logger.warning("Paramètres manquants ou invalides : 'action' ou 'texte' manquants.")
        return func.HttpResponse("Paramètres 'action' et 'texte' requis", status_code=400)
    logger.info(f"Action reçue : {action}")
    logger.info(f"Texte reçu : {texte[:50]}...")  # Affichage limité pour ne pas exposer de données sensibles dans les logs
    # Vérification si l'action est valide
    handler = handlers.get(action)
    if not handler:
        logger.error(f"Action inconnue : {action}")
        return func.HttpResponse("Action inconnue", status_code=400)
    logger.info(f"Exécution de l'action : {action}")
    # Exécuter la fonction correspondante et retourner le résultat
    try:
        result = handler(texte)
        logger.info(f"Résultat de l'action {action} : {result}")
        return func.HttpResponse(json.dumps({action: result}), mimetype="application/json", status_code=200)
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction pour l'action {action}: {str(e)}")
        return func.HttpResponse(f"Erreur lors de l'extraction : {str(e)}", status_code=500)






       
           
