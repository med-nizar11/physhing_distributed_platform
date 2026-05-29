from flask import Flask, request, redirect, url_for, session, render_template_string
import requests
import html

app = Flask(__name__)
app.secret_key = "change_this_secret_key_for_demo"

AUTH_URL = "http://127.0.0.1:5001"
GATEWAY_URL = "http://127.0.0.1:5010"
AUDIT_URL = "http://127.0.0.1:5003"


# -----------------------------
# OUTILS
# -----------------------------

def is_logged_in():
    return "token" in session


def get_headers():
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session.get('token', '')}"
    }


def safe(value):
    if value is None:
        return ""
    return html.escape(str(value))


def risk_badge(level):
    level = str(level).lower()

    if level == "élevé" or level == "eleve":
        return "badge-danger"
    elif level == "moyen":
        return "badge-warning"
    return "badge-success"


def page(title, content):
    username = session.get("username")
    role = session.get("role")

    nav_auth = ""
    if username:
        nav_auth = f"""
            <span class="user-info">Connecté : <strong>{safe(username)}</strong> ({safe(role)})</span>
            <a href="/logout" class="nav-btn danger-link">Déconnexion</a>
        """
    else:
        nav_auth = '<a href="/login" class="nav-btn">Connexion</a>'

    html_page = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>{safe(title)}</title>
        <style>
            * {{
                box-sizing: border-box;
            }}

            body {{
                margin: 0;
                font-family: Arial, Helvetica, sans-serif;
                background: #f4f7fb;
                color: #1f2937;
            }}

            .navbar {{
                background: linear-gradient(135deg, #0f172a, #1e3a8a);
                color: white;
                padding: 18px 40px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                box-shadow: 0 4px 15px rgba(0,0,0,0.15);
            }}

            .navbar h1 {{
                font-size: 22px;
                margin: 0;
                letter-spacing: 0.5px;
            }}

            .nav-right {{
                display: flex;
                align-items: center;
                gap: 12px;
            }}

            .user-info {{
                font-size: 14px;
                opacity: 0.95;
            }}

            .nav-btn {{
                color: white;
                text-decoration: none;
                background: rgba(255,255,255,0.15);
                padding: 9px 14px;
                border-radius: 8px;
                font-size: 14px;
                transition: 0.2s;
            }}

            .nav-btn:hover {{
                background: rgba(255,255,255,0.25);
            }}

            .danger-link {{
                background: #dc2626;
            }}

            .container {{
                width: 92%;
                max-width: 1150px;
                margin: 35px auto;
            }}

            .hero {{
                background: white;
                padding: 35px;
                border-radius: 18px;
                box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
                margin-bottom: 25px;
            }}

            .hero h2 {{
                margin-top: 0;
                color: #0f172a;
                font-size: 30px;
            }}

            .hero p {{
                color: #4b5563;
                line-height: 1.6;
            }}

            .grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
                gap: 20px;
            }}

            .card {{
                background: white;
                border-radius: 16px;
                padding: 24px;
                box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
                border: 1px solid #e5e7eb;
            }}

            .card h3 {{
                margin-top: 0;
                color: #1e3a8a;
            }}

            .card p {{
                color: #4b5563;
                font-size: 14px;
                line-height: 1.5;
            }}

            .btn {{
                display: inline-block;
                padding: 11px 16px;
                background: #2563eb;
                color: white;
                border: none;
                border-radius: 9px;
                text-decoration: none;
                cursor: pointer;
                font-size: 14px;
                margin-top: 8px;
            }}

            .btn:hover {{
                background: #1d4ed8;
            }}

            .btn-secondary {{
                background: #475569;
            }}

            .btn-secondary:hover {{
                background: #334155;
            }}

            .btn-danger {{
                background: #dc2626;
            }}

            .btn-danger:hover {{
                background: #b91c1c;
            }}

            form {{
                display: flex;
                flex-direction: column;
                gap: 14px;
            }}

            label {{
                font-weight: bold;
                color: #374151;
            }}

            input, textarea, select {{
                width: 100%;
                padding: 12px;
                border: 1px solid #d1d5db;
                border-radius: 9px;
                font-size: 14px;
                background: white;
            }}

            textarea {{
                min-height: 140px;
                resize: vertical;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                background: white;
                overflow: hidden;
                border-radius: 14px;
                box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
            }}

            th, td {{
                padding: 14px;
                border-bottom: 1px solid #e5e7eb;
                text-align: left;
                font-size: 14px;
            }}

            th {{
                background: #0f172a;
                color: white;
            }}

            tr:hover {{
                background: #f8fafc;
            }}

            .badge {{
                padding: 6px 10px;
                border-radius: 999px;
                color: white;
                font-size: 12px;
                font-weight: bold;
                display: inline-block;
            }}

            .badge-success {{
                background: #16a34a;
            }}

            .badge-warning {{
                background: #f59e0b;
            }}

            .badge-danger {{
                background: #dc2626;
            }}

            .alert {{
                padding: 15px;
                border-radius: 10px;
                margin-bottom: 18px;
            }}

            .alert-error {{
                background: #fee2e2;
                color: #991b1b;
                border: 1px solid #fecaca;
            }}

            .alert-success {{
                background: #dcfce7;
                color: #166534;
                border: 1px solid #bbf7d0;
            }}

            .analysis-box {{
                background: #0f172a;
                color: white;
                padding: 25px;
                border-radius: 16px;
                margin-top: 20px;
            }}

            .score {{
                font-size: 48px;
                font-weight: bold;
                margin: 10px 0;
            }}

            .reason-list li {{
                margin-bottom: 8px;
            }}

            .footer {{
                text-align: center;
                color: #64748b;
                padding: 30px;
                font-size: 13px;
            }}

            .code {{
                background: #f1f5f9;
                border-radius: 10px;
                padding: 14px;
                font-family: Consolas, monospace;
                overflow-x: auto;
            }}
        </style>
    </head>
    <body>
        <div class="navbar">
            <h1>Plateforme Phishing Distribuée</h1>
            <div class="nav-right">
                <a href="/" class="nav-btn">Accueil</a>
                <a href="/submit" class="nav-btn">Soumettre</a>
                <a href="/reports" class="nav-btn">Historique</a>
                <a href="/search" class="nav-btn">Recherche</a>
                <a href="/logs" class="nav-btn">Logs</a>
                {nav_auth}
            </div>
        </div>

        <div class="container">
            {content}
        </div>

        <div class="footer">
            Projet Cloud Computing / Applications réparties - Université Euromed
        </div>
    </body>
    </html>
    """

    return render_template_string(html_page)


# -----------------------------
# ROUTES INTERFACE
# -----------------------------

@app.route("/")
def home():
    content = """
    <div class="hero">
        <h2>Détection et qualification d’e-mails de phishing</h2>
        <p>
            Cette interface permet de se connecter, de soumettre un e-mail suspect,
            d’obtenir un score de risque, de consulter l’historique des signalements
            et de vérifier les logs d’audit.
        </p>
        <p>
            L’application repose sur une architecture distribuée :
            AuthService, GatewayService, AnalysisService RPC avec Pyro5,
            AuditService et SQLite.
        </p>
        <a href="/login" class="btn">Commencer</a>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Authentification</h3>
            <p>Connexion avec login, mot de passe hashé et token de session.</p>
        </div>

        <div class="card">
            <h3>Analyse phishing</h3>
            <p>Détection des mots urgents, URLs suspectes et demandes de données sensibles.</p>
        </div>

        <div class="card">
            <h3>Historique</h3>
            <p>Stockage des signalements dans une base SQLite avec score et justification.</p>
        </div>

        <div class="card">
            <h3>Audit</h3>
            <p>Traçabilité des actions sensibles et des erreurs importantes.</p>
        </div>
    </div>
    """
    return page("Accueil", content)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

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

            if response.status_code == 200:
                session["token"] = data["token"]
                session["username"] = data["username"]
                session["role"] = data["role"]
                return redirect(url_for("dashboard"))

            error = "Identifiants invalides."

        except requests.exceptions.RequestException:
            error = "AuthService est indisponible."

    alert = ""
    if error:
        alert = f'<div class="alert alert-error">{safe(error)}</div>'

    content = f"""
    <div class="card">
        <h2>Connexion</h2>
        {alert}
        <form method="POST">
            <div>
                <label>Nom d'utilisateur</label>
                <input type="text" name="username" placeholder="admin" required>
            </div>

            <div>
                <label>Mot de passe</label>
                <input type="password" name="password" placeholder="admin123" required>
            </div>

            <button type="submit" class="btn">Se connecter</button>
        </form>

        <p style="margin-top: 20px;">
            Comptes de test :
            <br>admin / admin123
            <br>analyst / analyst123
            <br>user / user123
        </p>
    </div>
    """

    return page("Connexion", content)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))

    content = f"""
    <div class="hero">
        <h2>Tableau de bord</h2>
        <p>Bienvenue <strong>{safe(session.get("username"))}</strong>.</p>
        <p>Rôle : <strong>{safe(session.get("role"))}</strong></p>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Soumettre un e-mail</h3>
            <p>Envoyer un e-mail suspect au moteur d’analyse.</p>
            <a href="/submit" class="btn">Soumettre</a>
        </div>

        <div class="card">
            <h3>Historique</h3>
            <p>Consulter les signalements déjà enregistrés.</p>
            <a href="/reports" class="btn">Voir l’historique</a>
        </div>

        <div class="card">
            <h3>Recherche</h3>
            <p>Rechercher par expéditeur, score ou mot-clé.</p>
            <a href="/search" class="btn">Rechercher</a>
        </div>

        <div class="card">
            <h3>Logs d’audit</h3>
            <p>Voir les dernières actions sensibles enregistrées.</p>
            <a href="/logs" class="btn">Voir les logs</a>
        </div>
    </div>
    """
    return page("Tableau de bord", content)


@app.route("/submit", methods=["GET", "POST"])
def submit_email():
    if not is_logged_in():
        return redirect(url_for("login"))

    result_html = ""

    if request.method == "POST":
        sender = request.form.get("sender", "")
        subject = request.form.get("subject", "")
        content_email = request.form.get("content", "")
        has_attachment = request.form.get("has_attachment") == "yes"

        try:
            response = requests.post(
                GATEWAY_URL + "/submit",
                headers=get_headers(),
                json={
                    "sender": sender,
                    "subject": subject,
                    "content": content_email,
                    "has_attachment": has_attachment
                },
                timeout=10
            )

            data = response.json()

            if response.status_code == 201:
                analysis = data.get("analysis", {})
                score = analysis.get("score")
                level = analysis.get("level")
                reasons = analysis.get("reasons", [])
                urls = analysis.get("urls_detected", [])

                reasons_html = "".join([f"<li>{safe(reason)}</li>" for reason in reasons])
                urls_html = "".join([f"<li>{safe(url)}</li>" for url in urls])

                if not urls_html:
                    urls_html = "<li>Aucune URL détectée</li>"

                result_html = f"""
                <div class="analysis-box">
                    <h2>Résultat de l’analyse</h2>
                    <p>Score de risque :</p>
                    <div class="score">{safe(score)}/100</div>
                    <p>
                        Niveau :
                        <span class="badge {risk_badge(level)}">{safe(level)}</span>
                    </p>

                    <h3>Justifications</h3>
                    <ul class="reason-list">{reasons_html}</ul>

                    <h3>URLs détectées</h3>
                    <ul class="reason-list">{urls_html}</ul>
                </div>
                """
            else:
                result_html = f"""
                <div class="alert alert-error">
                    Erreur : {safe(data.get("error", "Impossible de créer le signalement"))}
                </div>
                """

        except requests.exceptions.RequestException:
            result_html = """
            <div class="alert alert-error">
                GatewayService est indisponible.
            </div>
            """

    content = f"""
    <div class="card">
        <h2>Soumettre un e-mail suspect</h2>

        <form method="POST">
            <div>
                <label>Expéditeur déclaré</label>
                <input type="text" name="sender" value="support-security@fake-bank.tk" required>
            </div>

            <div>
                <label>Objet de l’e-mail</label>
                <input type="text" name="subject" value="URGENT votre compte est bloque" required>
            </div>

            <div>
                <label>Contenu de l’e-mail</label>
                <textarea name="content" required>Cliquez immediatement sur http://secure-update-bank.tk pour confirmer votre mot de passe</textarea>
            </div>

            <div>
                <label>Pièce jointe</label>
                <select name="has_attachment">
                    <option value="no">Non</option>
                    <option value="yes">Oui</option>
                </select>
            </div>

            <button type="submit" class="btn">Analyser l’e-mail</button>
        </form>
    </div>

    {result_html}
    """

    return page("Soumettre", content)


@app.route("/reports")
def reports():
    if not is_logged_in():
        return redirect(url_for("login"))

    try:
        response = requests.get(
            GATEWAY_URL + "/reports",
            headers=get_headers(),
            timeout=5
        )

        data = response.json()
        reports_list = data.get("reports", [])

        rows = ""

        for report in reports_list:
            rows += f"""
            <tr>
                <td>{safe(report.get("id"))}</td>
                <td>{safe(report.get("sender"))}</td>
                <td>{safe(report.get("subject"))}</td>
                <td>{safe(report.get("submitted_by"))}</td>
                <td>{safe(report.get("risk_score"))}</td>
                <td><span class="badge {risk_badge(report.get("risk_level"))}">{safe(report.get("risk_level"))}</span></td>
                <td><a href="/reports/{safe(report.get("id"))}" class="btn btn-secondary">Détail</a></td>
            </tr>
            """

        if not rows:
            rows = """
            <tr>
                <td colspan="7">Aucun signalement trouvé.</td>
            </tr>
            """

        content = f"""
        <div class="card">
            <h2>Historique des signalements</h2>
        </div>

        <table>
            <tr>
                <th>ID</th>
                <th>Expéditeur</th>
                <th>Objet</th>
                <th>Utilisateur</th>
                <th>Score</th>
                <th>Niveau</th>
                <th>Action</th>
            </tr>
            {rows}
        </table>
        """

    except requests.exceptions.RequestException:
        content = """
        <div class="alert alert-error">
            GatewayService est indisponible.
        </div>
        """

    return page("Historique", content)


@app.route("/reports/<int:report_id>")
def report_detail(report_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    try:
        response = requests.get(
            GATEWAY_URL + f"/reports/{report_id}",
            headers=get_headers(),
            timeout=5
        )

        data = response.json()

        if response.status_code != 200:
            content = f"""
            <div class="alert alert-error">
                {safe(data.get("error", "Signalement introuvable"))}
            </div>
            """
            return page("Détail", content)

        report = data.get("report", {})
        reasons = report.get("reasons", [])
        urls = report.get("urls_detected", [])

        reasons_html = "".join([f"<li>{safe(reason)}</li>" for reason in reasons])
        urls_html = "".join([f"<li>{safe(url)}</li>" for url in urls])

        if not urls_html:
            urls_html = "<li>Aucune URL détectée</li>"

        content = f"""
        <div class="card">
            <h2>Détail du signalement #{safe(report.get("id"))}</h2>

            <p><strong>Expéditeur :</strong> {safe(report.get("sender"))}</p>
            <p><strong>Objet :</strong> {safe(report.get("subject"))}</p>
            <p><strong>Utilisateur :</strong> {safe(report.get("submitted_by"))}</p>
            <p><strong>Date :</strong> {safe(report.get("submitted_at"))}</p>
            <p><strong>Pièce jointe :</strong> {safe(report.get("has_attachment"))}</p>

            <hr>

            <p><strong>Contenu :</strong></p>
            <div class="code">{safe(report.get("content"))}</div>
        </div>

        <div class="analysis-box">
            <h2>Analyse</h2>
            <div class="score">{safe(report.get("risk_score"))}/100</div>
            <p>
                Niveau :
                <span class="badge {risk_badge(report.get("risk_level"))}">
                    {safe(report.get("risk_level"))}
                </span>
            </p>

            <h3>Justifications</h3>
            <ul>{reasons_html}</ul>

            <h3>URLs détectées</h3>
            <ul>{urls_html}</ul>
        </div>
        """

    except requests.exceptions.RequestException:
        content = """
        <div class="alert alert-error">
            GatewayService est indisponible.
        </div>
        """

    return page("Détail", content)


@app.route("/search", methods=["GET", "POST"])
def search():
    if not is_logged_in():
        return redirect(url_for("login"))

    results_html = ""

    if request.method == "POST":
        sender = request.form.get("sender", "")
        risk_level = request.form.get("risk_level", "")
        keyword = request.form.get("keyword", "")

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
            reports_list = data.get("reports", [])

            rows = ""

            for report in reports_list:
                rows += f"""
                <tr>
                    <td>{safe(report.get("id"))}</td>
                    <td>{safe(report.get("sender"))}</td>
                    <td>{safe(report.get("subject"))}</td>
                    <td>{safe(report.get("risk_score"))}</td>
                    <td><span class="badge {risk_badge(report.get("risk_level"))}">{safe(report.get("risk_level"))}</span></td>
                    <td><a href="/reports/{safe(report.get("id"))}" class="btn btn-secondary">Détail</a></td>
                </tr>
                """

            if not rows:
                rows = """
                <tr>
                    <td colspan="6">Aucun résultat trouvé.</td>
                </tr>
                """

            results_html = f"""
            <div class="card" style="margin-top: 25px;">
                <h2>Résultats</h2>
            </div>

            <table>
                <tr>
                    <th>ID</th>
                    <th>Expéditeur</th>
                    <th>Objet</th>
                    <th>Score</th>
                    <th>Niveau</th>
                    <th>Action</th>
                </tr>
                {rows}
            </table>
            """

        except requests.exceptions.RequestException:
            results_html = """
            <div class="alert alert-error">
                GatewayService est indisponible.
            </div>
            """

    content = f"""
    <div class="card">
        <h2>Recherche de signalements</h2>

        <form method="POST">
            <div>
                <label>Expéditeur</label>
                <input type="text" name="sender" placeholder="ex: fake-bank">
            </div>

            <div>
                <label>Niveau de risque</label>
                <select name="risk_level">
                    <option value="">Tous</option>
                    <option value="faible">faible</option>
                    <option value="moyen">moyen</option>
                    <option value="élevé">élevé</option>
                </select>
            </div>

            <div>
                <label>Mot-clé</label>
                <input type="text" name="keyword" placeholder="ex: mot de passe">
            </div>

            <button type="submit" class="btn">Rechercher</button>
        </form>
    </div>

    {results_html}
    """

    return page("Recherche", content)


@app.route("/logs")
def logs():
    if not is_logged_in():
        return redirect(url_for("login"))

    try:
        response = requests.get(
            AUDIT_URL + "/logs",
            timeout=5
        )

        data = response.json()
        logs_list = data.get("logs", [])

        rows = ""

        for log in logs_list:
            rows += f"""
            <tr>
                <td>{safe(log.get("timestamp"))}</td>
                <td>{safe(log.get("event_type"))}</td>
                <td>{safe(log.get("username"))}</td>
                <td>{safe(log.get("status"))}</td>
                <td><div class="code">{safe(log.get("details"))}</div></td>
            </tr>
            """

        if not rows:
            rows = """
            <tr>
                <td colspan="5">Aucun log trouvé.</td>
            </tr>
            """

        content = f"""
        <div class="card">
            <h2>Logs d’audit</h2>
            <p>Cette page affiche les derniers événements de sécurité enregistrés par AuditService.</p>
        </div>

        <table>
            <tr>
                <th>Date</th>
                <th>Événement</th>
                <th>Utilisateur</th>
                <th>Statut</th>
                <th>Détails</th>
            </tr>
            {rows}
        </table>
        """

    except requests.exceptions.RequestException:
        content = """
        <div class="alert alert-error">
            AuditService est indisponible.
        </div>
        """

    return page("Logs", content)


@app.route("/test-unauthorized")
def test_unauthorized():
    try:
        response = requests.get(
            GATEWAY_URL + "/reports",
            timeout=5
        )

        content = f"""
        <div class="card">
            <h2>Test accès sans token</h2>
            <p>Code HTTP : {safe(response.status_code)}</p>
            <div class="code">{safe(response.text)}</div>
        </div>
        """

    except requests.exceptions.RequestException:
        content = """
        <div class="alert alert-error">
            GatewayService est indisponible.
        </div>
        """

    return page("Test Unauthorized", content)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5020, debug=True)