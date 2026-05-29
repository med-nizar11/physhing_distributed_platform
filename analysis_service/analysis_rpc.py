import re
import Pyro5.api


@Pyro5.api.expose
class AnalysisService:
    def analyze_email(self, email_data):
        """
        Analyse un email suspect et retourne un score de risque.
        """

        if not isinstance(email_data, dict):
            return {
                "score": 0,
                "level": "faible",
                "reasons": ["Données invalides"]
            }

        sender = str(email_data.get("sender", "")).lower()
        subject = str(email_data.get("subject", "")).lower()
        content = str(email_data.get("content", "")).lower()
        has_attachment = bool(email_data.get("has_attachment", False))

        full_text = subject + " " + content

        score = 0
        reasons = []

        # 1. Détection de mots urgents ou manipulateurs
        urgent_words = [
            "urgent",
            "immédiatement",
            "immediatement",
            "dernier avertissement",
            "attention",
            "bloqué",
            "bloque",
            "suspendu",
            "confirmer maintenant",
            "action requise"
        ]

        for word in urgent_words:
            if word in full_text:
                score += 20
                reasons.append(f"Mot urgent détecté : {word}")
                break

        # 2. Demande de données sensibles
        sensitive_words = [
            "mot de passe",
            "password",
            "carte bancaire",
            "numéro de carte",
            "numero de carte",
            "code secret",
            "identifiants",
            "login",
            "confirmer vos informations"
        ]

        for word in sensitive_words:
            if word in full_text:
                score += 30
                reasons.append(f"Demande d'information sensible détectée : {word}")
                break

        # 3. Détection automatique des URLs
        urls = re.findall(r"https?://[^\s]+", full_text)

        if urls:
            score += 15
            reasons.append("Présence d'une URL dans le message")

        # 4. Domaines suspects
        suspicious_domains = [
            ".tk",
            ".ru",
            ".cn",
            ".xyz",
            "bit.ly",
            "tinyurl",
            "shorturl",
            "free-login",
            "secure-update",
            "verify-account"
        ]

        for url in urls:
            for domain in suspicious_domains:
                if domain in url:
                    score += 25
                    reasons.append(f"Domaine ou URL suspect détecté : {url}")
                    break

        # 5. Pièce jointe annoncée
        attachment_words = [
            "pièce jointe",
            "piece jointe",
            "facture jointe",
            "document attaché",
            "document attache",
            "ouvrir le fichier"
        ]

        if has_attachment:
            score += 10
            reasons.append("Présence d'une pièce jointe signalée")

        for word in attachment_words:
            if word in full_text:
                score += 10
                reasons.append("Le message mentionne une pièce jointe")
                break

        # 6. Usurpation possible : banque, paypal, microsoft...
        impersonation_words = [
            "banque",
            "bank",
            "paypal",
            "microsoft",
            "google",
            "apple",
            "netflix",
            "amazon"
        ]

        for word in impersonation_words:
            if word in full_text:
                score += 15
                reasons.append(f"Possible usurpation d'identité : {word}")
                break

        # 7. Expéditeur bizarre
        suspicious_sender_parts = [
            "support-security",
            "account-verify",
            "no-reply-secure",
            "login-update"
        ]

        for part in suspicious_sender_parts:
            if part in sender:
                score += 20
                reasons.append("Adresse expéditeur suspecte")
                break

        # Limiter le score à 100
        if score > 100:
            score = 100

        # Déterminer le niveau de risque
        if score <= 30:
            level = "faible"
        elif score <= 60:
            level = "moyen"
        else:
            level = "élevé"

        if not reasons:
            reasons.append("Aucun indicateur fort de phishing détecté")

        return {
            "score": score,
            "level": level,
            "reasons": reasons,
            "urls_detected": urls
        }


def main():
    daemon = Pyro5.api.Daemon(host="127.0.0.1")

    try:
        ns = Pyro5.api.locate_ns(host="127.0.0.1", port=9090)
    except Exception:
        print("Erreur : Pyro5 Name Server non trouvé.")
        print("Lance d'abord cette commande dans un autre terminal :")
        print("python -m Pyro5.nameserver")
        return

    uri = daemon.register(AnalysisService)
    ns.register("phishing.analysis", uri)

    print("AnalysisService RPC lancé avec succès.")
    print("Nom du service : phishing.analysis")
    print("URI :", uri)

    daemon.requestLoop()


if __name__ == "__main__":
    main()