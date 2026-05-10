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

## 8) test_6_rce_static.py

### Test: test_no_rce_primitives_exist_in_application_code

Cosa controlla:
- Cerca nel codice applicativo primitive tipiche da RCE o command injection.
- Blocca l'introduzione di sink pericolosi come os.popen, os.system, eval, exec e subprocess con shell=True.

Come lo controlla:
1. Scansiona tutti i file Python sotto web/.
2. Ignora righe vuote e commenti.
3. Applica regex difensive per trovare primitive ad alto rischio.
4. Se trova corrispondenze, fallisce riportando file, riga e motivo.

Perché è utile:
- È un test di regressione sicurezza semplice ma efficace: segnala subito l'introduzione di codice che potrebbe portare a RCE.

## 9) test_7_upload_hardening.py

### Test: test_upload_rejects_executable_script_extensions

Cosa controlla:
- L'upload lato server rifiuta file con estensioni eseguibili o script ad alto rischio.

Come lo controlla:
1. Effettua login come alice.
2. Tenta upload di un file con nome `payload.py`.
3. Verifica redirect di ritorno alla pagina documenti.
4. Verifica che il titolo non compaia nella lista documenti.
5. Verifica che la UI mostri il messaggio `File type not allowed.`.

Perché è utile:
- Riduce il rischio di caricare file eseguibili che potrebbero essere abusati in catene di attacco lato server.

### Test: test_upload_accepts_safe_text_documents

Cosa controlla:
- L'hardening non rompe il caso lecito di upload documenti testuali.

Come lo controlla:
1. Effettua login come alice.
2. Carica un file `note.txt`.
3. Verifica che il documento compaia nella lista.

Perché è utile:
- Conferma che la mitigazione è mirata e non blocca il comportamento richiesto dall'applicazione.

## 10) test_9_privilege_escalation.py

### Test: test_privilege_escalation_direct_endpoint_access

Cosa controlla:
- Protezione dell'endpoint `/admin/users` contro accesso da utente standard.

Come lo controlla:
1. Login come alice.
2. Tentativo GET su `/admin/users`.
3. Verifica che la risposta sia 403 Forbidden.

Perché è utile:
- Isola il controllo di RBAC (Role-Based Access Control) su endpoint amministrativi chiave.

### Test: test_privilege_escalation_admin_action_as_user

Cosa controlla:
- Protezione dell'endpoint POST `/admin/users/<id>/disable` contro utenti non admin.

Come lo controlla:
1. Login come alice.
2. Tentativo POST su `/admin/users/<bob_id>/disable`.
3. Verifica che la risposta sia 403 Forbidden.

Perché è utile:
- Verifica che le azioni amministrative critiche siano protette da RBAC lato server.

### Test: test_privilege_escalation_session_tampering_cookie_injection

Cosa controlla:
- Resistenza del sistema alla manomissione del cookie di sessione.

Come lo controlla:
1. Login come alice e recupero del cookie di sessione.
2. Modifica del cookie (append di dati) per tentare tampering.
3. Tentativo di accesso a `/admin/users` con cookie manomesso.
4. Verifica che la sessione falsificata sia rifiutata o l'utente rediretto.

Perché è utile:
- Verifica che Flask validi la firma HMAC del cookie e rifiuti modifiche client-side.

### Test: test_privilege_escalation_disabled_user_session_persistence

Cosa controlla:
- Comportamento della sessione quando un utente attivo viene disabilitato.

Come lo controlla:
1. Login come alice e verifica accesso a /documents.
2. Admin disabilita alice via endpoint `/admin/users/<alice_id>/disable`.
3. Alice tenta di usare la vecchia sessione per accedere a `/documents`.
4. Verifica che l'accesso sia negato (o avverte se ancora consentito).

Perché è utile:
- Identifica se il backend invalida le sessioni quando un utente viene disabilitato (defensive measure).

### Test: test_privilege_escalation_force_admin_action_unauthenticated

Cosa controlla:
- Protezione del decorator `@login_required` su endpoint admin.

Come lo controlla:
1. Tenta GET su `/admin/users` senza autenticazione.
2. Verifica che la risposta sia redirect (302/303) verso login.

Perché è utile:
- Baseline per verificare che endpoint admin non siano accessibili senza autenticazione.

### Test: test_privilege_escalation_cross_site_request_forgery_admin_action

Cosa controlla:
- Comportamento dell'endpoint POST verso azioni amministrative (CSRF scenario).

Come lo controlla:
1. Login come alice.
2. POST verso `/admin/users/<id>/disable` senza CSRF token.
3. Verifica che la richiesta sia rifiutata (403, dato che alice non è admin).

Perché è utile:
- Verifica che anche se un attacco CSRF riuscisse a inviare la POST, il backend la rifiuterebbe grazie a is_admin_session().

### Test: test_idor_protection_download_endpoint

Cosa controlla:
- Protezione contro IDOR (Insecure Direct Object Reference) sull'endpoint `/documents/<id>/download`.
- Un utente autenticato (bob) non può scaricare un documento che appartiene a un altro utente (alice).

Come lo controlla:
1. Alice carica un documento e recupera il suo ID.
2. Bob tenta di accedere a `/documents/{document_id}/download`.
3. Si aspetta una risposta 403 Forbidden.

Perché è utile:
- Verifica che il sistema controlli l'autorizzazione lato server e non si fidi dell'ID fornito dal client.

### Test: test_idor_protection_details_endpoint

Cosa controlla:
- Protezione IDOR su `/documents/<id>` (visualizzazione dettagli).

Come lo controlla:
1. Alice carica un documento.
2. Bob tenta di accedere a `/documents/{document_id}`.
3. Si aspetta 403 e che il titolo del documento non sia presente nella risposta d'errore.

Perché è utile:
- Conferma che il controllo accessi è lato database e non utenti non autorizzati vedono informazioni sensibili.

### Test: test_idor_protection_share_endpoint

Cosa controlla:
- Protezione IDOR su `/documents/<id>/share`.
- Bob non può condividere il documento di Alice.

Come lo controlla:
1. Alice carica un documento.
2. Bob tenta POST su `/documents/{document_id}/share`.
3. Si aspetta 403 Forbidden.

Perché è utile:
- Isola il controllo di autorizzazione sull'azione di condivisione.

### Test: test_idor_protection_shared_download_endpoint

Cosa controlla:
- Protezione IDOR su `/shared/<id>/download`.
- Un documento non condiviso con un utente non è scaricabile tramite `/shared/<id>/download`.

Come lo controlla:
1. Alice carica un documento (non lo condivide con bob).
2. Bob tenta accesso a `/shared/{document_id}/download`.
3. Si aspetta 403 Forbidden (il documento non è nella lista di quelli condivisi con bob).

Perché è utile:
- Verifica che il controllo di autorizzazione su shared download sia specifico: il documento deve essere effettivamente condiviso.

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
- python3 -m pytest -q tests/test_6_rce_static.py
- python3 -m pytest -q tests/test_7_upload_hardening.py
- python3 -m pytest -q tests/test_8_idor_protection.py
- python3 -m pytest -q tests/test_9_privilege_escalation.py

## Lettura rapida dei risultati

- passed: comportamento atteso confermato.
- failed: c'è una regressione o un prerequisito non rispettato (servizio non avviato, credenziali non valide, endpoint non implementato, ecc.).
- errore tipico da distinguere: eseguire un file test con python diretto non equivale a eseguire pytest.
  Usare sempre python3 -m pytest ... per far girare realmente i test.
