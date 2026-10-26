# Graph Report - A2A_Scratch  (2026-10-25)

## Corpus Check
- 19 files · ~31,539 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 809 nodes · 1893 edges · 26 communities (24 shown, 2 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 43 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- JWT Scripts & Tampering
- Learning Docs & Concepts
- Attack Drill & Service Endpoints
- Agent HTTP Boundary
- ADK Agent & Stock Tool
- Bearer & Delegation Auth
- User Store
- Agent Token Lifecycle Tests
- Agent Human-to-Machine Tests
- Delegation Tests
- Delegation Authority API
- Identity Service Tests
- Token Issuer Tests
- Scope & Identity Tests
- Identity Config & Signing
- Authorization Policy Tests
- Key Rotation Tests
- Identity Forwarding Experiment
- Issuer Signing Config
- Agent Human Auth Tests
- Password Hashing
- Shared Test Support
- Identity Login API
- Environment Setup Script
- Role & Class Policy
- uv Environment Name

## God Nodes (most connected - your core abstractions)
1. `get()` - 63 edges
2. `make_token()` - 40 edges
3. `get_stock()` - 31 edges
4. `Day 05 learnings: JWTs, issuer, scopes, lifecycle, rotation` - 19 edges
5. `ask()` - 17 edges
6. `load_config()` - 16 edges
7. `run()` - 16 edges
8. `request_token()` - 15 edges
9. `verify_token()` - 15 edges
10. `human_token()` - 15 edges

## Surprising Connections (you probably didn't know these)
- `alice_token()` --calls--> `load_config()`  [INFERRED]
  tests/test_identity_forwarding.py → delegation_authority/config.py
- `login()` --references--> `post()`  [EXTRACTED]
  identity_service/app.py → scripts/attack_drill.py
- `test_missing_service_config_fails_startup()` --calls--> `load_trusted_keys()`  [EXTRACTED]
  tests/test_key_rotation.py → inventory_service/tokens.py
- `human_token()` --calls--> `load_config()`  [INFERRED]
  tests/test_agent_app.py → delegation_authority/config.py
- `human_token()` --calls--> `load_config()`  [INFERRED]
  tests/test_agent_http.py → delegation_authority/config.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Request pipeline: verify token -> scope -> role -> class -> SQLite** — docs_day05_learnings_bearer_token_auth, docs_day05_learnings_scopes, docs_day04_learnings_rbac, docs_day04_learnings_class_based_authorization, docs_day03_learnings_repository [EXTRACTED 1.00]
- **Signing-key rotation flow (trust new, switch issuer, retire old)** — docs_day05_key_rotation_runbook_service_config, docs_day05_key_rotation_runbook_issuer_config, docs_day05_key_rotation_runbook_overlap_phase, docs_day05_key_rotation_runbook_retire_phase, scripts_check_rotation [EXTRACTED 1.00]
- **Credential evolution: shared secret -> API key -> signed JWT** — readme_inventory_shared_secret, docs_day03_learnings_x_api_key_auth, docs_day05_learnings_rs256_jwt [INFERRED 0.85]

## Communities (26 total, 2 thin omitted)

### Community 0 - "JWT Scripts & Tampering"
Cohesion: 0.06
Nodes (46): claims_of(), tamper_sub(), issue_token(), main(), b64url_decode(), b64url_encode(), main(), run_experiments() (+38 more)

### Community 1 - "Learning Docs & Concepts"
Cohesion: 0.05
Nodes (40): Day 01 example tool call trace, function_declarations tool schema, found / not_found / error status dict, Day 01 learnings: ADK inventory agent, uv environment outside repo (UV_PROJECT_ENVIRONMENT), Day 02 learnings: credential check inside the tool, secrets.compare_digest constant-time comparison, Day 03 learnings: HTTP, headers, Postman, API-key auth (+32 more)

### Community 2 - "Attack Drill & Service Endpoints"
Cohesion: 0.05
Nodes (25): _clear_cache(), get_stock(), whoami(), _algorithms(), _authentication(), _claims(), Drill, edit_claim() (+17 more)

### Community 3 - "Agent HTTP Boundary"
Cohesion: 0.05
Nodes (17): consistent_error_body(), authenticate_human(), extract_bearer(), get_trust(), Human, HumanTrust, load_trust(), verify_human() (+9 more)

### Community 4 - "ADK Agent & Stock Tool"
Cohesion: 0.07
Nodes (21): get_stock(), _call_service(), fetch_stock(), _fetch_token(), get_delegation(), _get_token(), _invalidate(), _map_service_response() (+13 more)

### Community 5 - "Bearer & Delegation Auth"
Cohesion: 0.08
Nodes (20): authenticate(), authenticate_delegation(), Delegation, extract_bearer_token(), Principal, load_delegation_trust(), load_public_key(), load_trusted_keys() (+12 more)

### Community 6 - "User Store"
Cohesion: 0.09
Nodes (19): _connect(), create_user(), find_user(), normalize_username(), update_hash(), get_classification(), lookup_sku(), main() (+11 more)

### Community 7 - "Agent Token Lifecycle Tests"
Cohesion: 0.11
Nodes (29): get_stock(), Clock, clock(), test_10_calls_cost_1_issuer_call(), test_1_first_call_gets_a_token_then_calls_service(), test_2_second_call_before_expiry_reuses_token(), test_3_token_near_expiry_is_renewed_proactively(), test_3b_just_outside_the_margin_still_reuses() (+21 more)

### Community 8 - "Agent Human-to-Machine Tests"
Cohesion: 0.11
Nodes (27): agent(), ask(), _bad_human_tokens(), edit_claim(), human_token(), machine_calls(), real_machine_path(), post() (+19 more)

### Community 9 - "Delegation Tests"
Cohesion: 0.12
Nodes (25): actor(), ask(), authority(), delegate(), delegation(), edit(), human(), test_actor_must_prove_itself_for_this_authority() (+17 more)

### Community 10 - "Delegation Authority API"
Cohesion: 0.09
Nodes (14): consistent_error_body(), delegate(), DelegationRequest, _deny(), validation_error(), _verify(), AuthorityConfig, load_config() (+6 more)

### Community 11 - "Identity Service Tests"
Cohesion: 0.10
Nodes (18): db(), idp(), login(), stored_hash(), test_alice_correct_password_is_200(), test_alice_wrong_password_is_401(), test_another_users_password_is_401(), test_existing_inventory_jwt_security_unchanged() (+10 more)

### Community 12 - "Token Issuer Tests"
Cohesion: 0.13
Nodes (23): claims_of(), issuer_client(), request_token(), test_authentication_is_checked_before_scope(), test_bad_credentials_are_401(), test_caller_cannot_choose_sub(), test_entitled_client_can_request_less_than_its_entitlement(), test_identity_and_entitlement_come_from_issuer_registry() (+15 more)

### Community 13 - "Scope & Identity Tests"
Cohesion: 0.12
Nodes (22): make_token(), test_bare_x_human_user_still_grants_nothing(), test_identity_is_the_verified_sub(), test_validly_signed_unknown_identity_is_403_not_401(), test_attacker_cannot_pick_a_trusted_kid(), test_kid_cannot_be_a_path_or_url(), test_unknown_kid_is_401(), issue() (+14 more)

### Community 14 - "Identity Config & Signing"
Cohesion: 0.17
Nodes (10): IdentityConfig, load_config(), resolve_path(), issue_user_token(), load_private_key(), test_expired_token_is_rejected(), test_wrong_audience_is_rejected(), test_human_token_is_rejected_by_the_inventory_service() (+2 more)

### Community 15 - "Authorization Policy Tests"
Cohesion: 0.17
Nodes (15): get(), test_401_and_403_are_distinct(), test_caller_headers_cannot_change_identity_role_or_class(), test_class_comes_from_data_not_sku_name(), test_class_permission_comes_from_role_not_identity_name(), test_classification_failure_fails_closed(), test_denied_response_contains_no_protected_details(), test_error_body_shape_and_no_secret_leak() (+7 more)

### Community 16 - "Key Rotation Tests"
Cohesion: 0.18
Nodes (14): issue(), issuer_client(), kid_of(), sign_with(), test_full_rotation_overlap_then_retirement(), test_issuer_token_contains_active_kid(), test_key1_token_accepted_when_key1_trusted(), test_key2_token_accepted_when_key2_trusted() (+6 more)

### Community 17 - "Identity Forwarding Experiment"
Cohesion: 0.12
Nodes (10): test_repository_knows_nothing_about_auth(), alice_token(), test_admin_claim_does_not_lift_a_restricted_machine(), test_authorization_code_never_reads_the_claim(), test_claim_does_not_change_reader_outcomes(), test_claim_is_never_echoed_in_the_response(), test_claim_is_never_labelled_authenticated(), test_forged_header_cannot_inject_log_lines() (+2 more)

### Community 18 - "Issuer Signing Config"
Cohesion: 0.17
Nodes (8): test_bad_issuer_config_fails_startup(), test_bad_service_config_fails_startup(), test_relative_paths_resolve_from_project_root(), write(), test_issuer_refuses_a_public_key_file(), load_private_key(), load_signing_config(), resolve_path()

### Community 19 - "Agent Human Auth Tests"
Cohesion: 0.23
Nodes (12): agent(), ask(), downstream(), human_token(), tamper(), test_authenticate_human_rejects_malformed_headers(), test_authenticate_human_returns_the_subject(), test_invalid_credentials_get_one_generic_401() (+4 more)

### Community 20 - "Password Hashing"
Cohesion: 0.23
Nodes (7): hash_password(), verify_password(), test_garbage_hash_is_false_not_an_error(), test_nothing_is_logged(), test_the_hash_does_not_contain_the_password(), test_welcome123_hashed_twice_differs_and_both_verify(), test_wrong_password_is_false()

### Community 22 - "Identity Login API"
Cohesion: 0.24
Nodes (5): authenticate(), login(), LoginRequest, needs_rehash(), test_weak_hash_is_upgraded_on_next_successful_login()

### Community 23 - "Environment Setup Script"
Cohesion: 0.25
Nodes (7): GEMINI_JUDEGE, GEMINI_MODEL, GOOGLE_CLOUD_LOCATION, GOOGLE_CLOUD_PROJECT, GOOGLE_GENAI_USE_VERTEXAI, init.sh script, UV_PROJECT_ENVIRONMENT

### Community 24 - "Role & Class Policy"
Cohesion: 0.25
Nodes (3): is_allowed(), read_permission_for(), role_for()

## Knowledge Gaps
- **10 isolated node(s):** `GEMINI_JUDEGE`, `GEMINI_MODEL`, `GOOGLE_CLOUD_LOCATION`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_GENAI_USE_VERTEXAI` (+5 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 214 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `get()` connect `Authorization Policy Tests` to `Bearer & Delegation Auth`, `Delegation Tests`, `Token Issuer Tests`, `Scope & Identity Tests`, `Key Rotation Tests`, `Identity Forwarding Experiment`, `Shared Test Support`?**
  _High betweenness centrality (0.056) - this node is a cross-community bridge._
- **What connects `GEMINI_JUDEGE`, `GEMINI_MODEL`, `GOOGLE_CLOUD_LOCATION` to the rest of the system?**
  _10 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `JWT Scripts & Tampering` be split into smaller, more focused modules?**
  _Cohesion score 0.06260406260406261 - nodes in this community are weakly interconnected._
- **Why does `make_token()` connect `Scope & Identity Tests` to `JWT Scripts & Tampering`, `Attack Drill & Service Endpoints`, `Bearer & Delegation Auth`, `Agent Human-to-Machine Tests`, `Delegation Tests`, `Key Rotation Tests`, `Agent Human Auth Tests`, `Shared Test Support`?**
  _High betweenness centrality (0.038) - this node is a cross-community bridge._
- **Should `Learning Docs & Concepts` be split into smaller, more focused modules?**
  _Cohesion score 0.05017543859649123 - nodes in this community are weakly interconnected._
- **Why does `README: ADK Inventory Agent` connect `Learning Docs & Concepts` to `User Store`?**
  _High betweenness centrality (0.036) - this node is a cross-community bridge._
- **Should `Attack Drill & Service Endpoints` be split into smaller, more focused modules?**
  _Cohesion score 0.05023796932839767 - nodes in this community are weakly interconnected._