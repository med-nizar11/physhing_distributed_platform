# Plateforme distribuée de détection et qualification d’e-mails de phishing

## 1. Description du projet

Ce projet est une mini plateforme distribuée développée en Python.  
Elle permet à un utilisateur de se connecter, de soumettre un e-mail suspect, puis d’obtenir un score de risque de phishing : faible, moyen ou élevé.

L’application est composée de plusieurs services indépendants qui communiquent entre eux via HTTP/JSON et RPC avec Pyro5.

## 2. Architecture

```txt
Client console
     |
     v
GatewayService / SubmissionService
     |
     |---> AuthService
     |
     |---> AnalysisService RPC avec Pyro5
     |
     |---> AuditService
     |
     v
SQLite reports.db
