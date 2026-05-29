import requests
import json

GATEWAY_URL = "http://127.0.0.1:5010"
AUTH_URL = "http://127.0.0.1:5001"

token = None
current_user = None
current_role = None


def print_json(data):
    print(json.dumps(data, indent=4, ensure_ascii=False))


def pause():
    input("\nAppuie sur Entrée pour revenir au menu...")


def login():
    global token, current_user, current_role

    print("\n=== Connexion ===")
    username = input("Username: ")
    password = input("Password: ")

    try:
        response = requests.post(
            AUTH_URL + "/login",
            json={
                "username": username,
                "password": password
            },
            timeout=5
        )

        data = response.json()

        print("\nCode HTTP :", response.status_code)
        print("Réponse du serveur :")
        print_json(data)

        if response.status_code == 200:
            token = data["token"]
            current_user = data["username"]
            current_role = data["role"]

            print("\nConnexion réussie.")
            print(f"Utilisateur : {current_user}")
            print(f"Rôle : {current_role}")
        else:
            print("\nErreur : identifiants invalides.")

    except requests.exceptions.RequestException as e:
        print("\nErreur : AuthService indisponible.")
        print("Détail :", e)

    pause()


def get_headers():
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }


def submit_email():
    if not token:
        print("\nTu dois d'abord te connecter.")
        pause()
        return

    print("\n=== Soumission d'un e-mail suspect ===")

    sender = input("Expéditeur déclaré: ")
    subject = input("Objet de l'e-mail: ")
    content = input("Contenu de l'e-mail: ")

    attachment_answer = input("Pièce jointe ? oui/non: ").lower().strip()
    has_attachment = attachment_answer == "oui"

    email_data = {
        "sender": sender,
        "subject": subject,
        "content": content,
        "has_attachment": has_attachment
    }

    try:
        response = requests.post(
            GATEWAY_URL + "/submit",
            headers=get_headers(),
            json=email_data,
            timeout=10
        )

        print("\nCode HTTP :", response.status_code)

        try:
            data = response.json()
        except Exception:
            print("\nRéponse non JSON :")
            print(response.text)
            pause()
            return

        print("\nRéponse complète du serveur :")
        print_json(data)

        if response.status_code == 201:
            analysis = data.get("analysis", {})

            print("\n==============================")
            print("       SCORE DE RISQUE")
            print("==============================")
            print("Score :", analysis.get("score"))
            print("Niveau :", analysis.get("level"))

            print("\nJustifications :")
            for reason in analysis.get("reasons", []):
                print("-", reason)

            print("\nURLs détectées :")
            urls = analysis.get("urls_detected", [])
            if urls:
                for url in urls:
                    print("-", url)
            else:
                print("Aucune URL détectée.")

        else:
            print("\nLe signalement n'a pas été créé.")
            print("Vérifie les services ou le token.")

    except requests.exceptions.RequestException as e:
        print("\nErreur : GatewayService indisponible.")
        print("Détail :", e)

    pause()


def list_reports():
    if not token:
        print("\nTu dois d'abord te connecter.")
        pause()
        return

    try:
        response = requests.get(
            GATEWAY_URL + "/reports",
            headers=get_headers(),
            timeout=5
        )

        data = response.json()

        print("\n=== Liste des signalements ===")
        print_json(data)

    except requests.exceptions.RequestException as e:
        print("\nErreur : GatewayService indisponible.")
        print("Détail :", e)

    pause()


def report_detail():
    if not token:
        print("\nTu dois d'abord te connecter.")
        pause()
        return

    report_id = input("ID du signalement: ")

    try:
        response = requests.get(
            GATEWAY_URL + f"/reports/{report_id}",
            headers=get_headers(),
            timeout=5
        )

        data = response.json()

        print("\n=== Détail du signalement ===")
        print_json(data)

    except requests.exceptions.RequestException as e:
        print("\nErreur : GatewayService indisponible.")
        print("Détail :", e)

    pause()


def search_reports():
    if not token:
        print("\nTu dois d'abord te connecter.")
        pause()
        return

    print("\n=== Recherche ===")
    print("Laisse vide si tu ne veux pas utiliser un critère.")

    sender = input("Recherche par expéditeur: ")
    risk_level = input("Recherche par niveau faible/moyen/élevé: ")
    keyword = input("Recherche par mot-clé: ")

    params = {}

    if sender:
        params["sender"] = sender

    if risk_level:
        params["risk_level"] = risk_level

    if keyword:
        params["keyword"] = keyword

    try:
        response = requests.get(
            GATEWAY_URL + "/search",
            headers=get_headers(),
            params=params,
            timeout=5
        )

        data = response.json()

        print("\n=== Résultats de recherche ===")
        print_json(data)

    except requests.exceptions.RequestException as e:
        print("\nErreur : GatewayService indisponible.")
        print("Détail :", e)

    pause()


def show_menu():
    print("\n==============================")
    print(" Plateforme Phishing Distribuée")
    print("==============================")

    if current_user:
        print(f"Connecté : {current_user} ({current_role})")
    else:
        print("Non connecté")

    print("\n1. Se connecter")
    print("2. Soumettre un e-mail suspect")
    print("3. Lister les signalements")
    print("4. Consulter le détail d'un signalement")
    print("5. Rechercher")
    print("6. Quitter")


def main():
    while True:
        show_menu()
        choice = input("\nChoix: ")

        if choice == "1":
            login()
        elif choice == "2":
            submit_email()
        elif choice == "3":
            list_reports()
        elif choice == "4":
            report_detail()
        elif choice == "5":
            search_reports()
        elif choice == "6":
            print("Au revoir.")
            break
        else:
            print("Choix invalide.")
            pause()


if __name__ == "__main__":
    main()