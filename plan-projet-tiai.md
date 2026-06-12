# Tiai — Console de gestion de parc informatique (Natimai)

> Plateforme centralisée de pilotage du parc Windows.
> **Phase 1 (urgente)** : Microsoft Defender. **Phases ultérieures (fin d'année)** : Windows Update, déploiement logiciel, inventaire.
>
> *« Tīa'i » — en reo tahiti : gardien, vigile, garder, protéger.

---

## 1. Vision & périmètre

Construire un agent léger déployé par GPO sur les postes Windows, un backend central qui collecte l'état des postes et orchestre des actions, et une console web de supervision.

| Module | Priorité | Horizon |
|---|---|---|
| **Defender** : état, scans à distance, mise à jour des signatures | 🔴 Urgent | Maintenant |
| Windows Update | 🟠 Moyen | Fin d'année |
| Déploiement logiciel | 🟡 Bas | Fin d'année |
| Inventaire matériel/logiciel | 🟡 Bas | Fin d'année |

Tout le projet est pensé pour que l'ajout des modules suivants réutilise **le même agent, le même canal de communication et le même modèle de commandes** — seuls les types de commandes et les données remontées changent.

---

## 2. Remarques & ajustements proposés

Synthèse des décisions structurantes. Le détail technique est repris dans les sections suivantes.

### 2.1 — Modèle de communication : *polling* plutôt que *push* ✅ changement recommandé

Tu décris « envoyer les demandes de scan aux clients », ce qui suppose que le serveur ouvre une connexion vers chaque poste. C'est fragile : NAT, pare-feu, postes portables hors réseau, postes éteints. **Recommandation : inverser le sens.** L'agent interroge le serveur à intervalle régulier (*polling*) :

1. l'agent appelle le serveur (heartbeat) → remonte son état Defender ;
2. **la même réponse** lui renvoie les commandes en attente (scan rapide / complet / update) ;
3. l'agent exécute, puis poste le résultat.

Le serveur ne « pousse » jamais : il **met des commandes en file**, les agents les récupèrent. Avantages : traverse NAT/pare-feu sans configuration, gère naturellement les postes hors-ligne, et 1000 postes deviennent une charge triviale.

> **Latence** : une action « lancer un scan sur tous les postes » s'applique à chaque poste lors de son prochain *poll*. Prévoir deux intervalles : un long pour la remontée d'état (ex. 15 min) et un court pour la récupération de commandes (ex. 1 min). Si du quasi-temps-réel est nécessaire plus tard → SSE ou WebSocket en option.

### 2.2 — « 1000 connexions » : à requalifier

En modèle *polling*, il n'y a **pas** 1000 connexions persistantes mais de brèves requêtes étalées dans le temps : ~1 à 3 req/s en moyenne pour 1000 postes. Un seul conteneur backend + un *worker* suffisent largement. **Inutile de sur-dimensionner** (pas de Kafka, pas de cluster). Le seul point d'attention est le pool de connexions PostgreSQL (asyncpg) bien réglé.

### 2.3 — Identité stable des postes ✅ point critique

Le nom de poste et le domaine peuvent changer (renommage, migration). Identifier un poste par son `hostname` casserait l'historique et créerait des doublons. **Recommandation : un identifiant stable** :
- soit le `MachineGuid` de Windows (`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`),
- soit un UUID généré au premier démarrage et persisté localement.

Le `hostname` et le `domain` deviennent de simples **attributs** rattachés à cet identifiant.

### 2.4 — Authentification : auto-enrôlement + token par poste ✅ ajustement

Une clé partagée unique en variable d'environnement contrôle tout le parc : si **un** poste la fuite, n'importe qui peut usurper **n'importe quel** poste et déclencher des scans partout. On garde l'enrôlement automatique (zéro validation manuelle) **tout en** passant à un token par poste. Deux secrets distincts :

- un **secret d'enrôlement** partagé, déployé par GPO (registre ACL `SYSTEM` ou DPAPI), qui ne sert **qu'à** s'enregistrer ;
- un **token unique par poste**, émis automatiquement au premier contact.

Flux (*trust on first use*) :
1. Au 1er démarrage, l'agent lit son UUID stable, puis appelle `POST /enroll` avec l'en-tête `X-Enrollment-Secret`.
2. Le serveur valide le secret, crée le poste, génère un token aléatoire fort, en stocke **seulement le hash**, et renvoie le token **une seule fois**.
3. L'agent stocke le token chiffré (DPAPI) ; tous les appels suivants utilisent `Authorization: Bearer <token>`. Le secret d'enrôlement ne resservira plus.

Le secret partagé n'autorise que l'*enrôlement*, jamais le *contrôle* : une fuite permet au pire de créer de faux postes (bruit détectable), pas d'usurper un poste réel ni de lancer un scan. **Garde-fous** : signaler/auditer tout ré-enrôlement d'un `machine_uuid` connu (poste réinstallé vs vol de token) ; bouton de **révocation** de token côté console (force un ré-enrôlement). Implémenté dès **M1/M2**, pas reporté au durcissement.

### 2.5 — TLS : dès le départ, via **Caddy** + AC interne ✅ décidé

Envoyer le token d'authentification en HTTP clair, c'est l'exposer. On met donc le TLS **dès le MVP**, sans complexité : un service **Caddy** en frontal (reverse-proxy) termine le TLS et sert backend + frontend. Pas besoin de Traefik (utile surtout pour du routage dynamique multi-services).

Le certificat : un certificat serveur émis par l'**AC interne** de l'entreprise (AD CS) pour le nom du serveur (ex. `tiai.natimai.local`). Les postes du domaine font **déjà confiance** à cette AC racine → aucun avertissement. Bonus : le client HTTP de Go sous Windows utilise le **magasin système**, donc le certificat AC interne est validé sans config côté agent. À défaut d'AD CS : certificat auto-signé + racine poussée par GPO. Let's Encrypt seulement si le serveur a un nom DNS public (rare en interne).

### 2.6 — Accès à Defender : WMI plutôt que shell PowerShell

Plutôt que de lancer un processus `powershell.exe Get-MpComputerStatus` à chaque cycle (coûteux, fragile), interroger directement **WMI** dans l'espace de noms `ROOT\Microsoft\Windows\Defender` :

| Donnée | Source WMI | Équivalent PowerShell |
|---|---|---|
| État (signatures, RTP, scans) | classe `MSFT_MpComputerStatus` | `Get-MpComputerStatus` |
| Historique des menaces | `MSFT_MpThreatDetection` / `MSFT_MpThreat` | `Get-MpThreatDetection` |
| Lancer un scan | méthode `Start` de `MSFT_MpScan` | `Start-MpScan -ScanType Quick/Full` |
| MAJ signatures | méthode `Update` de `MSFT_MpSignature` | `Update-MpSignature` |

En Go : `github.com/yusufpapurcu/wmi` (+ `go-ole`). Garder le repli PowerShell pour les opérations non exposées en WMI.

### 2.7 — Déduplication des menaces

Chaque détection Defender porte un `DetectionID` unique. **Contrainte d'unicité `(machine_id, detection_id)`** en base + `INSERT ... ON CONFLICT DO NOTHING` (upsert) → aucun doublon, même si l'agent remonte plusieurs fois la même menace.

### 2.8 — Expiration des commandes ✅ à ne pas oublier

Un portable éteint 3 semaines ne doit pas, à son retour, déclencher un scan complet demandé il y a 20 jours. **Chaque commande porte un `expires_at`** ; passé ce délai, elle est marquée `expired` et n'est plus distribuée.

### 2.9 — Robustesse de l'agent

- File locale : si le serveur est injoignable, l'agent garde ses remontées et réessaie (back-off).
- Commandes idempotentes.
- **Signature de code** du binaire (détail en M6) : un certificat de **signature de code émis par l'AC interne**, distribué en *Éditeurs approuvés* par GPO, suffit pour un outil interne — inutile d'acheter un certificat public. Réduit les faux positifs Defender/SmartScreen et active le listage par publisher (AppLocker/WDAC).
- Compte de service : `LocalSystem` (droits admin nécessaires pour piloter Defender).

### 2.10 — Configuration : fichier **et** registre

GPO sait déployer les deux. Recommandation : fichier `C:\ProgramData\Tiai\config.yaml` comme source principale, **surchargé** par des clés de registre si présentes (utile pour pousser un réglage ponctuel par GPO sans réécrire le fichier). La clé sensible : idéalement via registre/DPAPI plutôt qu'en clair dans le YAML.

### 2.11 — Impact sur la stack

L'usage d'**ARQ implique Redis**. La stack docker-compose côté serveur devient donc : PostgreSQL + Redis + backend + worker + frontend + **Caddy** (reverse-proxy + TLS). **Les agents Windows ne sont pas dans Docker** (ils tournent sur les postes).

---

## 3. Architecture cible

```
   POSTES WINDOWS (hors Docker)                 SERVEUR (docker compose)
 ┌───────────────────────────┐         ┌─────────────────────────────────────┐
 │  Agent Tiai (Go)        │  HTTPS  │  Caddy : reverse-proxy + TLS         │
 │  • Service Windows        │ ──────► │            │                        │
 │  • lit WMI Defender       │ ◄────── │     ┌──────┴──────┐                  │
 │  • poll heartbeat         │ cmds    │     │  Backend    │  FastAPI         │
 │  • exécute scans/update   │         │     │  (uvicorn)  │                  │
 └───────────────────────────┘         │     └──┬───────┬──┘                  │
            ▲                           │        │       │                    │
            │ déploiement GPO           │   ┌────┴───┐ ┌─┴──────┐             │
            │ (MSI/EXE + config)        │   │Postgres│ │ Redis  │             │
            └───────────────────────────┘   └────────┘ └───┬────┘             │
                                            │      ┌────────┴────────┐         │
                                            │      │ Worker (ARQ)    │         │
                                            │      │ nettoyage+alerts│         │
                                            │      └─────────────────┘         │
                                            │  ┌──────────────┐                │
                                            │  │ Frontend     │ Quasar/Vue     │
                                            │  └──────────────┘                │
                                            └─────────────────────────────────┘
```

**Services docker-compose (côté serveur)**

| Service | Rôle |
|---|---|
| `caddy` | Reverse-proxy + **terminaison TLS** (certificat AC interne) ; route le backend et sert le build Quasar |
| `backend` | API FastAPI (uvicorn/gunicorn) |
| `worker` | Tâches ARQ (nettoyage postes inactifs, envoi d'alertes) |
| `db` | PostgreSQL (volume persistant) |
| `redis` | File ARQ + cache léger |
| `frontend` | Build Quasar statique servi par nginx |

---

## 4. Modèle de données (esquisse)

```text
machines
  id                uuid    PK (généré serveur)
  machine_uuid      text    UNIQUE   -- identité stable (MachineGuid/UUID agent)
  hostname          text             -- attribut, peut changer
  domain            text
  os_version        text
  agent_version     text
  -- état Defender (dérivé de MSFT_MpComputerStatus)
  rtp_enabled              bool
  av_enabled               bool
  signature_version        text
  signature_last_updated   timestamptz
  signature_age_days       int
  last_quick_scan          timestamptz
  last_full_scan           timestamptz
  is_up_to_date            bool       -- calculé (âge signatures + RTP)
  first_seen        timestamptz
  last_seen         timestamptz       -- = date de dernière connexion (UI)
  created_at, updated_at timestamptz
  INDEX (hostname), (domain), (last_seen), (is_up_to_date)

threats
  id              bigserial PK
  machine_id      uuid    FK → machines.id
  detection_id    text             -- identifiant unique Defender
  threat_name     text
  severity        text
  category        text
  status          text             -- active / quarantined / removed / allowed
  action_taken    text
  detected_at     timestamptz
  raw             jsonb
  UNIQUE (machine_id, detection_id)   -- déduplication
  INDEX (machine_id), (detected_at), (status)

commands               -- file de commandes (une ligne par poste, même en broadcast)
  id              uuid    PK
  machine_id      uuid    FK → machines.id
  type            text             -- quick_scan / full_scan / update_signatures
  status          text             -- pending / delivered / running / succeeded / failed / expired
  created_by      text
  created_at      timestamptz
  expires_at      timestamptz
  delivered_at    timestamptz
  started_at, finished_at timestamptz
  result_output   text
  error           text
  INDEX (machine_id, status), (expires_at)
```

> Toujours stocker en **UTC (`timestamptz`)**. Le « scan demandé sur tous les postes » crée N lignes `commands` en une insertion groupée.

---

## 5. Contrat d'API (esquisse)

**Côté agent** (auth : secret d'enrôlement pour `/enroll`, puis `Authorization: Bearer <token-poste>`)

| Méthode | Endpoint | Rôle |
|---|---|---|
| `POST` | `/api/v1/agent/enroll` | 1er contact, en-tête `X-Enrollment-Secret` : `machine_uuid`, `hostname`, `domain`, `os`, `agent_version` → **renvoie le token unique du poste** (une seule fois). Idempotent. |
| `POST` | `/api/v1/agent/heartbeat` | Remonte l'état Defender + menaces. **Renvoie les commandes en attente.** |
| `POST` | `/api/v1/agent/commands/{id}/result` | Résultat d'exécution d'une commande. |

**Côté console** (auth : session/JWT plus tard ; MVP simplifié)

| Méthode | Endpoint | Rôle |
|---|---|---|
| `GET` | `/api/v1/machines?search=&domain=&status=&page=` | Liste filtrable/paginée. |
| `GET` | `/api/v1/machines/{id}` | Détail d'un poste + menaces. |
| `GET` | `/api/v1/stats/overview` | KPIs dashboard. |
| `GET` | `/api/v1/threats?...` | Menaces actives du parc. |
| `POST`| `/api/v1/commands` | Crée une/des commande(s) : cible (ids ou filtre) + type. |
| `GET` | `/api/v1/commands?status=` | Suivi des commandes. |

> Fusionner *heartbeat* et *récupération de commandes* en **un seul appel** divise par deux le trafic agent.

---

## 6. Plan par étapes (jalons)

> Estimations indicatives en jours-homme pour **un développeur expérimenté**, à ajuster selon l'équipe. La priorité est de sortir une **tranche verticale fonctionnelle** au plus vite (M1) pour valider le contrat agent↔serveur avant d'épaissir chaque couche.

### M0 — Fondations *(2–3 j)*
- Mono-repo : `/agent` (Go), `/backend` (FastAPI), `/frontend` (Quasar), `/deploy` (compose, **Caddyfile**).
- `docker-compose` squelette : db + redis + backend + frontend + **caddy** qui démarrent, **HTTPS dès le départ** (Caddy + certificat de l'AC interne).
- Migrations de schéma (Alembic) avec les 3 tables.
- Préparer en amont le **certificat de signature de code** (modèle « Code Signing » sur l'AC interne) pour la chaîne de build.
- Conventions : logs structurés, `/health`, versionnement d'API (`/api/v1`).
- **DoD** : `docker compose up` lève la stack en **HTTPS**, `/health` répond, migrations OK.

### M1 — Tranche verticale minimale *(3–5 j)* 🎯
- Agent Go : service Windows minimal, lit `MSFT_MpComputerStatus` via WMI, envoie un heartbeat **en HTTPS**.
- Backend : `enroll` (valide le secret d'enrôlement, **émet le token par poste**) + `heartbeat` (upsert machine, met à jour `last_seen`, auth par token).
- Agent : stockage **chiffré du token** (DPAPI), réutilisé aux appels suivants.
- Frontend : une page listant les postes connus avec leur `last_seen`.
- **DoD** : un poste réel s'auto-enrôle, apparaît dans l'UI et son état se rafraîchit, le tout en HTTPS.

### M2 — Agent Defender complet *(5–8 j)*
- Lecture complète de l'état (signatures, RTP, dates de scans) + remontée des menaces (`MSFT_MpThreatDetection`) avec `detection_id`.
- Récupération + exécution des commandes : `quick_scan`, `full_scan`, `update_signatures`.
- Remontée du résultat d'exécution.
- Config YAML + surcharge registre ; identité stable (`MachineGuid`/UUID).
- File locale + back-off si serveur injoignable.
- **DoD** : depuis un appel API, on déclenche un scan/MAJ sur un poste réel et le résultat remonte.

### M3 — Backend complet *(5–7 j)*
- Déduplication menaces (contrainte + upsert).
- File de commandes : création unitaire et **groupée** (« tous » / par filtre), `expires_at`, transitions d'état.
- Endpoints stats (`/stats/overview`) : total parc, à jour / non à jour, postes avec menaces, postes inactifs depuis X.
- Recherche/filtrage `/machines` (nom, domaine, statut), pagination.
- Garde-fou de ré-enrôlement (`machine_uuid` déjà connu → signalé) + **révocation de token** (kill-switch) côté API.
- Réglage du pool asyncpg pour la charge.
- **DoD** : KPIs cohérents, recherche fonctionnelle, commande de masse distribuée correctement.

### M4 — Console (Frontend) *(6–9 j)*
- Dashboard : cartes KPI + liste d'alertes (postes non à jour, menaces actives).
- Recherche/filtres (nom, domaine, statut, inactivité).
- Vue détail poste : état Defender, historique menaces, dernières commandes.
- Sélection multiple → actions de masse (scan rapide/complet, MAJ) avec suivi du statut des commandes.
- **DoD** : un admin pilote tout le cycle depuis l'UI sans toucher à l'API.

### M5 — Durcissement *(4–6 j)*
- *(TLS et token par poste sont déjà en place depuis M0–M1.)*
- Authentification de la console (login admin / JWT) + **journal d'audit** (qui a lancé quel scan).
- **ARQ** : job de nettoyage (postes inactifs depuis X mois → archivage/suppression) + notification des alertes (e-mail SMTP ou webhook Teams/Slack).
- Rotation des tokens + limitation de débit côté API.
- **DoD** : console authentifiée, alertes envoyées automatiquement, actions tracées.

### M6 — Packaging, signature & déploiement GPO *(3–5 j)*
- Build de l'agent en **MSI** (ou EXE + script d'installation de service).
- **Signature du binaire et du MSI** dans le pipeline, avec le certificat de signature de l'AC interne :
  `signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 agent.exe`
  (`/tr` + `/td` = horodatage RFC 3161 : la signature survit à l'expiration du certificat).
- **GPO** : distribuer le certificat de signature dans le magasin *Éditeurs approuvés* des postes ; déployer le paquet + la configuration (fichier/registre) ; pousser la racine de l'AC interne si nécessaire.
- Documentation d'exploitation (mise à jour de l'agent, désinstallation, dépannage).
- **DoD** : agent signé déployé et reconnu de confiance sur un OU pilote.

➡️ **Fin de la Phase 1 (Defender).** Les jalons suivants relèvent de la fin d'année.

### Phase 2 — Windows Update *(fin d'année)*
Réutilise l'agent et la file de commandes. Nouveaux types de commandes (rechercher / installer des mises à jour, redémarrer) et nouvelles données remontées (mises à jour en attente, KB installés). Brique sensible (gestion des redémarrages, fenêtres de maintenance) → à cadrer séparément.

### Phase 3 — Déploiement logiciel + inventaire *(fin d'année)*
- Inventaire : remontée matériel/logiciel (réutilise heartbeat avec un nouveau bloc de données).
- Déploiement : nouveau type de commande « installer un paquet » + dépôt de paquets (à concevoir : stockage, intégrité, versions).

---

## 7. Sécurité — feuille de route

| Étape | Mesure |
|---|---|
| MVP (M0–M1) | **TLS dès le départ** (Caddy + AC interne) ; **auto-enrôlement** : secret d'enrôlement partagé → **token unique par poste** (DPAPI) ; identité = `machine_uuid`. |
| Durcissement (M5) | Auth console (JWT) ; garde-fou de ré-enrôlement + révocation de token ; journal d'audit ; moindre privilège + limitation de débit sur l'API. |
| Plus tard | Rotation automatique des tokens ; mTLS ; attestation d'identité AD à l'enrôlement ; RBAC console. |

Points permanents : binaire agent **signé**, validation stricte des entrées API, limitation de débit côté agent pour éviter l'effet « troupeau ».

---

## 8. Risques & points d'attention

- **Postes portables hors réseau** : le modèle *polling* gère bien le cas, mais si le serveur doit être atteignable depuis Internet/VPN, prévoir l'exposition sécurisée (reverse-proxy, IP filtrée, VPN).
- **Droits de l'agent** : `LocalSystem` est puissant ; le binaire signé et la chaîne de déploiement deviennent une cible de choix → soigner la sécurité de la build.
- **Cohérence des dates Defender** : certaines propriétés WMI valent `0`/`null` si aucun scan n'a eu lieu — gérer ces cas dans le calcul de `is_up_to_date`.
- **Faux doublons** : un poste réinstallé reçoit parfois un nouveau `MachineGuid` → prévoir une réconciliation manuelle dans l'UI (fusion de postes).
- **Effet de masse** : « scan complet sur tout le parc » peut saturer postes et réseau → permettre l'étalement (les commandes sont récupérées au *poll*, ce qui étale naturellement, mais documenter le comportement).

---

## 9. Stack technique — récapitulatif

| Couche | Choix | Note |
|---|---|---|
| Agent | **Go** | Binaire statique unique, idéal GPO, faible empreinte, bon support service Windows (`golang.org/x/sys/windows/svc` ou `kardianos/service`), WMI via `yusufpapurcu/wmi`. **Alternative** : C#/.NET — intégration Windows native plus riche et packaging MSI/signature plus simple, mais runtime à gérer. Go reste mon choix par défaut ici. |
| Backend | **FastAPI** (async) + asyncpg/SQLAlchemy | Conforme à ton choix. |
| Base | **PostgreSQL** | Conforme. |
| File de tâches | **ARQ** + **Redis** | Nettoyage + alertes. Redis ajouté à la stack. |
| Frontend | **Quasar / Vue 3** | Conforme. |
| Infra | docker-compose + **Caddy** (reverse-proxy + TLS) | TLS **dès le départ**, certificat de l'AC interne (déjà approuvée par les postes du domaine). Traefik inutile ici. |

---

## Questions ouvertes (pour affiner le plan)

1. Les postes portables sortent-ils du réseau d'entreprise (besoin d'un serveur joignable via VPN/Internet) ?
2. Quelle taille d'équipe sur le projet (pour caler les estimations) ?
3. Environnement 100 % AD/domaine, ou postes en workgroup à prévoir ?
4. Canal d'alerte souhaité : e-mail, Teams, Slack, autre ?
