# Guida ai test

Questa guida descrive i test presenti in `tests/`, cosa verificano e come.

## Prerequisiti

- Applicazione raggiungibile su `http://localhost:8000` (o `APP_BASE_URL`).
- Database inizializzato con utenti seed (`admin`, `alice`, `bob`).
- Dipendenze installate nel venv del progetto.

## 1) test_smoke.py

### test_health_endpoint

Scenario di riferimento:
- Baseline operativa (pre-condizione comune a tutti gli scenari).

Cosa controlla:
- L'endpoint `/health` risponde e il servizio è operativo.

Come lo controlla:
1. Polling su `/health` con timeout breve.
2. Verifica payload JSON con `status = ok`.

Perché è utile:
- Fallisce subito se stack/app non sono avviati.

## 2) test_delivery_auth_flow.py

### test_login_logout_flow

Scenario di riferimento:
- Baseline autenticazione e gestione sessione.

Cosa controlla:
- Ciclo completo login/logout e validità sessione.

Come lo controlla:
1. Login valido (redirect 302/303).
2. Accesso a `/documents` consentito.
3. Logout.
4. Nuovo accesso a `/documents` negato via redirect login.

Perché è utile:
- Verifica che la sessione venga davvero creata e invalidata.

## 3) test_1_download.py

### test_download_document_requires_authorized_access

Scenario di riferimento:
- Baseline controllo accessi su risorse documento (owner/non-owner).

Cosa controlla:
- Download consentito al proprietario.
- Download negato ad altro utente.

Come lo controlla:
1. Alice carica un documento.
2. Alice scarica e verifica contenuto.
3. Bob tenta lo stesso download.
4. Atteso `404` (resource cloaking anti-IDOR).

Perché è utile:
- Previene IDOR e riduce enumeration degli oggetti.

## 4) test_2_share.py

### test_share_document_requires_owner_or_admin_and_enables_access_for_target_user

Scenario di riferimento:
- Baseline autorizzazione su condivisione/revoca documento.

Cosa controlla:
- Solo owner/admin possono condividere/revocare.
- Utente condiviso accede finché share è attiva.

Come lo controlla:
1. Alice carica e condivide verso Bob.
2. Bob vede documento in `/shared` e dettagli.
3. Alice revoca.
4. Bob non vede più il documento; accessi diretti non autorizzati tornano `404`.
5. Bob tenta share non autorizzata e riceve `404`.

Perché è utile:
- Verifica policy di condivisione e anti-tampering URL.

## 5) test_3_shared_download.py

### test_shared_download_requires_active_share

Scenario di riferimento:
- Baseline vincolo di accesso legato a share attiva.

Cosa controlla:
- `/shared/<id>/download` funziona solo con share attiva.

Come lo controlla:
1. Alice condivide verso Bob.
2. Bob scarica con successo.
3. Alice revoca.
4. Bob ritenta e riceve `404`.

Perché è utile:
- Garantisce che l'autorizzazione dipenda dallo stato corrente dello share.

## 6) test_4_admin_users.py

### test_admin_users_requires_admin_role

Scenario di riferimento:
- Scenario 8 (Administrative RBAC bypass): controllo accesso pagina admin.

Cosa controlla:
- `/admin/users` accessibile solo ad admin.

Come lo controlla:
1. Admin accede (`200`).
2. Alice accede (`403`).

Perché è utile:
- Verifica RBAC su superficie amministrativa.

## 7) test_5_admin_user_toggle.py

### test_admin_enable_disable_endpoints_enforce_rbac_and_toggle_user_status

Scenario di riferimento:
- Scenario 8 (Administrative RBAC bypass): azioni admin critiche enable/disable.

Cosa controlla:
- Enable/disable utente richiede admin.
- Utente disabilitato non può autenticarsi.

Come lo controlla:
1. Admin disabilita Bob.
2. Login Bob fallisce.
3. Admin riabilita Bob.
4. Login Bob torna valido.
5. Alice non-admin non può disabilitare altri.

Perché è utile:
- Copre controlli di stato account e RBAC su azioni critiche.

## 8) test_6_rce_static.py

### test_no_rce_primitives_exist_in_application_code

Scenario di riferimento:
- Hardening codice applicativo contro primitive RCE (controllo statico).

Cosa controlla:
- Assenza primitive pericolose (`os.system`, `os.popen`, `eval`, `exec`, `subprocess(..., shell=True)`).

Come lo controlla:
1. Scansione regex dei `.py` sotto `web/`.
2. Fallisce con file/riga se trova sink critici.

Perché è utile:
- Blocca regressioni che potrebbero introdurre RCE.

## 9) test_7_upload_hardening.py

### test_upload_rejects_executable_script_extensions

Scenario di riferimento:
- Hardening upload contro catene upload-to-RCE.

Cosa controlla:
- Upload blocca estensioni eseguibili/script.

Come lo controlla:
1. Upload di `payload.py`.
2. Verifica messaggio `File type not allowed.`.
3. Verifica assenza del documento in lista.

Perché è utile:
- Riduce vettori upload-to-RCE.

### test_upload_accepts_safe_text_documents

Scenario di riferimento:
- Hardening upload: regressione funzionale positiva su file leciti.

Cosa controlla:
- Upload legittimo (`.txt`) resta funzionante.

Come lo controlla:
1. Upload di `note.txt`.
2. Verifica presenza in lista.

Perché è utile:
- Conferma hardening non distruttivo.

## 10) test_10_brute_force.py

### test_brute_force_user_enumeration_same_message
### test_brute_force_account_lockout_triggers
### test_brute_force_account_lockout_message
### test_brute_force_valid_user_not_affected_by_other_lockout
### test_brute_force_ip_rate_limit_triggers
### test_brute_force_security_headers_on_429

Scenario di riferimento:
- Scenario 4 (Brute force / credential stuffing).

Cosa controlla:
- Difese ATO su `/login`: anti-enumeration, lockout per account, rate limiting IP, coerenza header su 429.

Come lo controlla:
1. Confronta errori login per utente inesistente/password errata.
2. Verifica lockout dopo N tentativi falliti.
3. Verifica isolamento lockout tra account.
4. Verifica rate limiting per IP.
5. Verifica header sicurezza su risposte throttled.

Perché è utile:
- Mitiga brute force e credential stuffing automatizzati.

## 11) test_11_session_hijacking.py

### test_session_cookie_flags_present_on_login
### test_session_replay_rejected_on_fingerprint_mismatch
### test_hsts_and_csp_headers_are_present
### test_client_script_avoids_innerhtml_sink
### test_https_forced_uses_secure_host_prefixed_cookie

Scenario di riferimento:
- Scenario 5 (Session hijacking).

Cosa controlla:
- Difese anti-session hijacking: cookie hardening, anti-replay fingerprint, header HSTS/CSP, regressione XSS sink.

Come lo controlla:
1. Verifica `Set-Cookie` post-login (`HttpOnly`, `SameSite`).
2. Simula replay cookie con User-Agent diverso e attende redirect login.
3. Verifica presenza HSTS e CSP.
4. Verifica che `web/static/script.js` non usi `innerHTML`.
5. Se `FORCE_HTTPS=1`, verifica cookie `Secure` e nome `__Host-session`.

Perché è utile:
- Riduce rischio furto/replay sessione.

## 12) test_12_idor_attack_tree.py

### test_idor_attack_tree_sequential_id_tampering_is_blocked
### test_idor_attack_tree_shared_endpoint_requires_explicit_share

Scenario di riferimento:
- Scenario 6 (IDOR attack tree / misuse case).

Cosa controlla:
- Scenario 6 (misuse case + attack tree): ID predictability, URL tampering, bypass ownership check.

Come lo controlla:
1. Alice crea documento privato.
2. Bob prova ID adiacenti (`id-1`, `id`, `id+1`, `id+2`) su details/download.
3. Verifica sempre `404` uniforme (nessun leak esistenza).
4. Verifica `/shared/<id>/download` senza share attiva (`404`).

Perché è utile:
- Copre esplicitamente il vettore IDOR dell'albero d'attacco.

## 13) test_8_idor_protection.py

### test_idor_protection_download_endpoint
### test_idor_protection_details_endpoint
### test_idor_protection_share_endpoint
### test_idor_protection_shared_download_endpoint

Scenario di riferimento:
- Scenario 6 (IDOR): regressioni protezione endpoint core.

Cosa controlla:
- Hardening IDOR su endpoint documento/share/shared download.

Come lo controlla:
1. Bob prova accesso a risorse di Alice via ID diretto.
2. Verifica risposta `404` uniforme sui path non autorizzati.

Perché è utile:
- Mantiene regressione specifica anti-IDOR su endpoint core.

## 14) test_9_privilege_escalation.py

### test_privilege_escalation_direct_endpoint_access
### test_privilege_escalation_admin_action_as_user
### test_privilege_escalation_session_tampering_cookie_injection
### test_privilege_escalation_disabled_user_session_persistence
### test_privilege_escalation_force_admin_action_unauthenticated
### test_privilege_escalation_cross_site_request_forgery_admin_action

Scenario di riferimento:
- Scenario 8 (Administrative RBAC bypass / privilege escalation).

Cosa controlla:
- Escalation privilegi su superfici admin/session/CSRF.

Come lo controlla:
1. Verifica blocco endpoint admin a utenti standard.
2. Verifica blocco POST admin non autorizzate.
3. Verifica robustezza cookie firmato contro tampering.
4. Verifica invalidazione sessione utente disabilitato.
5. Verifica `@login_required` su admin.
6. Verifica blocco CSRF su POST sensibili.

Perché è utile:
- Copre i principali vettori di privilege escalation applicativa.

## 15) test_13_revocation_consistency.py

### test_revocation_immediate_effect_with_active_session
### test_authenticated_responses_disable_caching

Scenario di riferimento:
- Scenario 7 (Persistent access post-revocation).

Cosa controlla:
- Scenario 7 (Persistent Access Post-Revocation): un utente precedentemente autorizzato non deve mantenere accesso dopo revoke.
- Header anti-cache su risposte autenticate per evitare contenuti stale.

Come lo controlla:
1. Alice condivide un documento con Bob.
2. Bob accede con sessione valida ai tre endpoint (`/documents/<id>`, `/documents/<id>/download`, `/shared/<id>/download`).
3. Alice revoca l'accesso.
4. Bob, con la stessa sessione già aperta, ritenta gli endpoint.
5. Verifica revoca immediata (`404` uniforme su tutti i path).
6. Verifica `Cache-Control: no-store, no-cache, must-revalidate`, `Pragma: no-cache`, `Expires: 0` su endpoint autenticato.

Perché è utile:
- Blocca il vettore di abuso basato su stato autorizzativo stale (session-only checks, cache invalida, revoca non rivalidata).

## 16) test_14_monitoring_regression.py

### test_monitoring_regression_denied_access_logging_hooks_present

Scenario di riferimento:
- Scenario 6 (IDOR): residuo monitoring anti-probing.

Cosa controlla:
- Regressione del monitoring anti-probing (Scenario 6 residuo): i punti di audit logging per accessi negati non devono sparire dal codice.

Come lo controlla:
1. Scansiona `web/app/app.py`.
2. Verifica presenza helper `log_denied_document_access` e formato log con action/doc_id/user_id/ip/status.
3. Verifica hook su tutte le action richieste: `details`, `share`, `revoke`, `download`, `shared_download`.

Perché è utile:
- Protegge da regressioni silenziose sul monitoring, mantenendo tracciabilità degli accessi negati.

## 17) test_15_sqli_attack_tree.py

### test_sqli_attack_tree_blocks_suspicious_search_payload_documents
### test_sqli_attack_tree_blocks_suspicious_search_payload_shared
### test_sqli_attack_tree_search_functionality_remains_usable_for_legit_terms
### test_sqli_attack_tree_no_dynamic_sql_string_concatenation_regression

Scenario di riferimento:
- Scenario 9 (SQL Injection via search/list).

Cosa controlla:
- Blocco dei payload SQLi in query string `search` su `/documents` e `/shared`.
- Continuità funzionale su ricerche legittime.
- Regressione statica contro pattern comuni di SQL dinamico non sicuro.

Come lo controlla:
1. Invia payload SQLi tipici (`UNION SELECT`, `OR 1=1 --`) e verifica `400 Invalid search query`.
2. Verifica che una ricerca lecita filtri correttamente i risultati.
3. Scansiona il sorgente per prevenire reintroduzione di `execute(f"...")` o pattern simili.

Perché è utile:
- Riduce il rischio di estrazione dati sensibili via SQL injection e previene regressioni future.

## 18) test_16_stored_xss_attack_tree.py

### test_stored_xss_attack_tree_rejects_malicious_title_payload
### test_stored_xss_attack_tree_sanitizes_filename_and_no_raw_script_rendered
### test_stored_xss_attack_tree_static_regression_no_unsafe_template_sinks

Scenario di riferimento:
- Scenario 10 (Stored XSS via metadata/filename).

Cosa controlla:
- Blocco payload XSS nella title metadata in fase upload.
- Normalizzazione filename malevolo e assenza di script raw in UI.
- Regressione statica contro sink template non sicuri (`|safe`).

Come lo controlla:
1. Prova upload con title `<script>...` e verifica rifiuto con messaggio di errore.
2. Prova upload con filename malevolo e verifica che il valore raw non venga renderizzato.
3. Scansiona i template principali per confermare che l'escaping non sia disabilitato.

Perché è utile:
- Riduce il rischio di furto sessione via Stored XSS e previene bypass futuri lato rendering.

## 19) test_17_storage_dos_attack_tree.py

### test_storage_dos_attack_tree_upload_flood_triggers_rate_limit
### test_storage_dos_attack_tree_quota_controls_present_regression

Scenario di riferimento:
- Scenario 11 (Storage Saturation DoS via upload flooding).

Cosa controlla:
- Throttling degli upload ad alta frequenza (flood) con risposta `429`.
- Presenza regressione dei controlli anti-saturazione (quote per utente/globali e guard-rail storage).

Come lo controlla:
1. Esegue upload rapidi e ripetuti fino al trigger del rate limit upload.
2. Verifica `429` e presenza header sicurezza sulla risposta throttled.
3. Scansiona il sorgente per confermare presenza dei marker dei controlli DoS storage.

Perché è utile:
- Riduce rischio interruzione servizio per esaurimento spazio/throughput via upload automatizzati.

## 20) test_18_supply_chain_poisoning.py

### test_supply_chain_poisoning_controls_are_locked_down
### test_supply_chain_poisoning_lockfile_covers_all_packages

Scenario di riferimento:
- Scenario 12 (Supply Chain Poisoning / dependency confusion / manifest tampering).

Cosa controlla:
- Installazione dipendenze solo da lock file con hash verification.
- Assenza di dipendenze inutilizzate nel manifest runtime.
- Coerenza tra pacchetti bloccati e relativi hash.

Come lo controlla:
1. Verifica che `web/Dockerfile` installi da `web/requirements.lock` con `--require-hashes`.
2. Verifica che `web/requirements.txt` non contenga `PyYAML` non usato.
3. Verifica che ogni voce del lock abbia un hash SHA256.

Perché è utile:
- Mitiga poisoning del manifest e sostituzione di pacchetti lungo la supply chain.

## 21) test_19_secret_leakage_build_logs.py

### test_secret_leakage_workflows_use_log_redaction_on_failure
### test_secret_leakage_redaction_script_masks_common_patterns
### test_secret_leakage_workflows_avoid_plaintext_debug_commands

Scenario di riferimento:
- Scenario 13 (Compromise system secrets via build logs).

Cosa controlla:
- I workflow CI/CD non devono pubblicare log grezzi potenzialmente sensibili in caso di failure.
- Lo script di redazione deve coprire pattern di secret leakage comuni.
- Devono essere assenti comandi di debug che possono dumpare variabili sensibili in chiaro.

Come lo controlla:
1. Verifica che i failure path usino `docker compose ... logs | .github/scripts/redact_ci_logs.sh`.
2. Verifica che lo script contenga pattern di redazione per password/secret/token/URI credenziali.
3. Verifica assenza di `printenv` e `set -x` nei workflow CI/CD.

Perché è utile:
- Riduce il rischio di esposizione accidentale di credenziali nei build logs.

## Esecuzione consigliata

Eseguire tutti i test:
- `.venv/bin/python -m pytest -q`

Eseguire un singolo file:
- `.venv/bin/python -m pytest -q tests/test_smoke.py`
- `.venv/bin/python -m pytest -q tests/test_delivery_auth_flow.py`
- `.venv/bin/python -m pytest -q tests/test_1_download.py`
- `.venv/bin/python -m pytest -q tests/test_2_share.py`
- `.venv/bin/python -m pytest -q tests/test_3_shared_download.py`
- `.venv/bin/python -m pytest -q tests/test_4_admin_users.py`
- `.venv/bin/python -m pytest -q tests/test_5_admin_user_toggle.py`
- `.venv/bin/python -m pytest -q tests/test_6_rce_static.py`
- `.venv/bin/python -m pytest -q tests/test_7_upload_hardening.py`
- `.venv/bin/python -m pytest -q tests/test_10_brute_force.py`
- `.venv/bin/python -m pytest -q tests/test_11_session_hijacking.py`
- `.venv/bin/python -m pytest -q tests/test_12_idor_attack_tree.py`
- `.venv/bin/python -m pytest -q tests/test_8_idor_protection.py`
- `.venv/bin/python -m pytest -q tests/test_9_privilege_escalation.py`
- `.venv/bin/python -m pytest -q tests/test_13_revocation_consistency.py`
- `.venv/bin/python -m pytest -q tests/test_14_monitoring_regression.py`
- `.venv/bin/python -m pytest -q tests/test_15_sqli_attack_tree.py`
- `.venv/bin/python -m pytest -q tests/test_16_stored_xss_attack_tree.py`
- `.venv/bin/python -m pytest -q tests/test_17_storage_dos_attack_tree.py`
- `.venv/bin/python -m pytest -q tests/test_18_supply_chain_poisoning.py`
- `.venv/bin/python -m pytest -q tests/test_19_secret_leakage_build_logs.py`

## Lettura rapida dei risultati

- `passed`: comportamento atteso confermato.
- `failed`: regressione o prerequisito non rispettato.
- Eseguire sempre tramite `pytest` (`python -m pytest`), non con esecuzione diretta del file.
