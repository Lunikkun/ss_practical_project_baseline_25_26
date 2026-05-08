# Guida ai test

Questo file descrive i test presenti nella cartella tests, cosa controllano e come lo fanno.

## Prerequisiti

- Applicazione raggiungibile su http://localhost:8000 oppure su URL impostato via variabili ambiente.
- Database inizializzato con gli utenti richiesti (admin, alice, bob).
- Dipendenze Python installate (requests, pytest).

## 1) test_smoke.py

### Test: test_health_endpoint

Cosa controlla:
- Verifica che il servizio sia avviato e che l'endpoint di health risponda correttamente.

Come lo controlla:
- Chiama periodicamente GET /health con timeout breve (polling) finché il servizio risponde oppure scade il timeout.
- Quando riceve risposta valida, verifica che il payload JSON contenga status = ok.

Perché è utile:
- È un test smoke: conferma rapidamente che stack e connettività di base funzionano prima dei test funzionali.

## 2) test_delivery_auth_flow.py

### Test: test_login_logout_flow

Cosa controlla:
- Flusso completo di autenticazione e invalidazione sessione.

Come lo controlla:
1. Esegue POST /login con credenziali valide di alice.
2. Si aspetta redirect (302 o 303) dopo login riuscito.
3. Accede a GET /documents e si aspetta 200 (pagina protetta accessibile con sessione valida).
4. Esegue GET /logout e si aspetta redirect (302 o 303).
5. Riprova GET /documents e si aspetta redirect (302 o 303), quindi sessione revocata.

Perché è utile:
- Garantisce che login e logout non solo rispondano, ma cambino davvero lo stato della sessione.

## 3) test_1_download.py

### Test: test_download_document_requires_authorized_access

Cosa controlla:
- Controllo accessi sull'endpoint di download documento.
- Caso positivo: il proprietario del documento può scaricare.
- Caso negativo: un altro utente non autorizzato riceve 403.

Come lo controlla:
1. Attende disponibilità servizio via GET /health.
2. Login come alice (atteso redirect 302/303).
3. Upload di un file testo unico via POST /documents/upload.
4. Recupero ID documento leggendo la tabella di GET /documents con regex HTML.
5. Download come alice da GET /documents/<id>/download:
   - atteso status 200
   - atteso contenuto binario uguale a quello caricato
6. Login come bob e tentativo download dello stesso documento:
   - atteso status 403 Forbidden

Perché è utile:
- Valida contemporaneamente funzionalità endpoint e autorizzazione applicativa (owner vs non owner).

## 4) test_2_share.py

### Test: test_share_document_requires_owner_or_admin_and_enables_access_for_target_user

Cosa controlla:
- Endpoint di condivisione documento (POST /documents/<id>/share).
- Solo owner/admin possono condividere.
- L'utente destinatario ottiene accesso al documento condiviso.
- La policy semplificata consente la condivisione verso qualsiasi utente esistente.

Come lo controlla:
1. Attende disponibilità servizio via GET /health.
2. Login come alice.
3. Upload documento e recupero ID da /documents.
4. Estrae l'id di bob dalla form di share in /documents/<id>.
5. POST share come alice verso bob:
   - atteso redirect 302/303.
6. Login come bob e accesso a /documents/<id>:
   - atteso status 200 (accesso consentito tramite share).
7. Tentativo di share dello stesso documento da bob:
   - atteso status 403 (non owner/non admin).

Perché è utile:
- Copre sia il controllo di autorizzazione sull'azione di share, sia l'effetto funzionale della condivisione.

## 5) test_3_shared_download.py

### Test: test_shared_download_requires_active_share

Cosa controlla:
- Endpoint GET /shared/<id>/download.
- Download consentito solo se esiste una condivisione attiva verso l'utente autenticato.

Come lo controlla:
1. Login come alice e upload documento.
2. Share del documento verso bob.
3. Login come bob e download da /shared/<id>/download:
   - atteso status 200 e contenuto corretto.
4. Revoca accesso da alice.
5. Nuovo tentativo download da bob:
   - atteso status 403.

Perché è utile:
- Isola il terzo endpoint in un test dedicato e verifica il vincolo di sicurezza principale: accesso legato a share attiva.

## 6) test_4_admin_users.py

### Test: test_admin_users_requires_admin_role

Cosa controlla:
- Endpoint GET /admin/users.
- Accesso consentito solo ad admin.

Come lo controlla:
1. Login come admin e GET /admin/users:
   - atteso status 200.
   - attesa presenza della tabella utenti con alice e bob.
2. Login come alice e GET /admin/users:
   - atteso status 403.

Perché è utile:
- Isola il controllo RBAC del pannello amministrativo utenti.

## 7) test_5_admin_user_toggle.py

### Test: test_admin_enable_disable_endpoints_enforce_rbac_and_toggle_user_status

Cosa controlla:
- Endpoint POST /admin/users/<id>/enable.
- Endpoint POST /admin/users/<id>/disable.
- RBAC admin-only sui due endpoint.

Come lo controlla:
1. Login come admin e recupero id utente bob dalla tabella admin.
2. Disable bob via endpoint disable:
   - atteso redirect 302/303.
3. Verifica login bob mentre disabilitato:
   - atteso fallimento login (status 200 su pagina login con credenziali rifiutate).
4. Enable bob via endpoint enable:
   - atteso redirect 302/303.
5. Verifica login bob riuscito e accesso a /documents.
6. Verifica RBAC: alice tenta disable e riceve 403.

Perché è utile:
- Isola il comportamento dei due endpoint di toggle e la protezione admin-only.

## Esecuzione consigliata

Eseguire tutti i test:
- python3 -m pytest -q

Eseguire un singolo file:
- python3 -m pytest -q tests/test_smoke.py
- python3 -m pytest -q tests/test_delivery_auth_flow.py
- python3 -m pytest -q tests/test_1_download.py
- python3 -m pytest -q tests/test_2_share.py
- python3 -m pytest -q tests/test_3_shared_download.py
- python3 -m pytest -q tests/test_4_admin_users.py
- python3 -m pytest -q tests/test_5_admin_user_toggle.py

## Lettura rapida dei risultati

- passed: comportamento atteso confermato.
- failed: c'è una regressione o un prerequisito non rispettato (servizio non avviato, credenziali non valide, endpoint non implementato, ecc.).
- errore tipico da distinguere: eseguire un file test con python diretto non equivale a eseguire pytest.
  Usare sempre python3 -m pytest ... per far girare realmente i test.
