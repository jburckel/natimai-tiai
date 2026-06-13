# Tiai — Agent (Windows)

Service Windows léger, déployé par GPO, qui interroge le serveur (polling),
remonte l'état Defender et exécute les commandes (scan / mise à jour signatures).

## Layout

```
main.go                    commandes CLI (run / init-config / version)
internal/
  config/   config ProgramData (config.json), token DPAPI (M1)
  identity/ résolution identité (SMBIOS UUID validé / repli UUID agent) + empreinte
  api/      client HTTP (enroll / heartbeat / result)
  collector/ lecture Defender via WMI (stub — port depuis natimai-windows-console)
  agent/    boucle de polling + exécution des commandes
  models/   types de la couche transport
```

## Statut

Squelette buildable (stdlib uniquement). À porter depuis
`natimai-windows-console`, qui implémente déjà :

- le **service Windows** (`golang.org/x/sys/windows/svc`) — install/uninstall/start/stop ;
- l'accès **WMI Defender** (`MSFT_MpComputerStatus`, `MSFT_MpScan`, `MSFT_MpSignature`) ;
- la **file locale** + back-off, le logging, la lecture du `MachineGuid`.

## Build & essai

```bash
cd agent
go build -o tiai-agent.exe .
./tiai-agent.exe init-config --api-url https://tiai.natimai.local --machine-uuid <MachineGuid>
./tiai-agent.exe run
```

L'agent s'auto-enrôle au 1er démarrage (en-tête `X-Enrollment-Secret`), stocke
le token reçu, puis n'utilise plus que `Authorization: Bearer <token>`.
