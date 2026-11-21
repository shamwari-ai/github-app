# The Rust port: parity with the TypeScript Worker

`shamwari-github-mcp` was a ~3.9k-line TypeScript Worker (MCP SDK v2, `tsx`
tests, `vite-plus`). It is now Rust on [`workers-rs`](https://github.com/cloudflare/workers-rs)
(`worker` 0.9), compiled to `wasm32-unknown-unknown` and bundled by
`worker-build`. What it does is written down in
[behaviour-contract.md](behaviour-contract.md). This page shows that it still
does it: where each TypeScript module went, where each TypeScript test went,
and everything that is deliberately different.

> `package.json` holds only `name`, `version` and `private`. It exists because
> the org's Release version check treats removing a version from it as a reset;
> CI fails if its version differs from `Cargo.toml`'s. Bump both together.

## Layout

```text
src/lib.rs            module list
src/worker_entry.rs   wasm32 only: the one place that touches the Workers runtime
src/platform.rs       the Platform trait: HTTP, Workers AI, clock, tracing span
src/router.rs         routes, CORS, Origin, bearer gate (pure over Req/Resp)
src/tests/            the ported test suite and its fixtures
```

Everything except `worker_entry.rs` is plain Rust over `Platform`, so it runs
under `cargo test` on the host. The wasm build is exercised separately by
`scripts/smoke-local.sh` (see [Verification](#verification)).

## Module map

| TypeScript       | Rust                                   | Notes                                                                       |
| ---------------- | -------------------------------------- | --------------------------------------------------------------------------- |
| `src/index.ts`   | `src/router.rs`, `src/worker_entry.rs` | Routing is pure; the runtime glue converts request and response             |
| `src/env.ts`     | `src/config.rs`                        | `Config` is built from `[vars]` and secrets; every field optional           |
| `src/auth.ts`    | `src/auth.rs`                          | RS256 verification with the `rsa` crate instead of WebCrypto                |
| `src/github.ts`  | `src/github.rs`                        | JWT signing with the `rsa` crate; DER wrapper kept and tested               |
| `src/mcp.ts`     | `src/mcp.rs`                           | The SDK is replaced by a hand-written dual-era JSON-RPC layer               |
| `src/review.ts`  | `src/review.rs`                        | Same prompt, schema, annotation and posting rules                           |
| `src/webhook.ts` | `src/webhook.rs`                       | HMAC via `hmac` + `sha2`; the mention matcher is hand-written               |
| `src/a2a.ts`     | `src/a2a.rs`                           | Same 1.0 wire format                                                        |
| `src/setup.ts`   | `src/setup.rs`                         | The one-click form now posts to the enterprise                              |
| `src/tracing.ts` | `src/tracing.rs`, `Platform::in_span`  | Real custom spans through `worker::observability`                           |
| `src/origin.ts`  | `src/origin.rs`                        |                                                                             |
| `test/*.test.ts` | `src/tests/*.rs`                       | One file per original, plus `mod.rs` for fixtures (the old `mcp-helper.ts`) |

## Test map

Every TypeScript test has a Rust counterpart. Tests that the TypeScript ran in
a loop (`der`, `resource`) are one Rust test looping the same cases.

| File                     | TypeScript test                                                               | Rust test                                                                                 |
| ------------------------ | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `test/a2a.test.ts`       | the card declares the 1.0 protocol version                                    | `a2a::the_card_declares_the_1_0_protocol_version`                                         |
| `test/a2a.test.ts`       | the card advertises only what is implemented                                  | `a2a::the_card_advertises_only_what_is_implemented`                                       |
| `test/a2a.test.ts`       | the security scheme uses the v1.0 member-name discriminator                   | `a2a::the_security_scheme_uses_the_v1_0_member_name_discriminator`                        |
| `test/a2a.test.ts`       | the card fails closed when WORKOS_AUTHORIZATION_SERVER is unset               | `a2a::the_card_fails_closed_when_workos_authorization_server_is_unset`                    |
| `test/a2a.test.ts`       | the card fails closed when WORKOS_AUTHORIZATION_SERVER is not an https origin | `a2a::the_card_fails_closed_when_the_authorization_server_is_not_an_https_origin`         |
| `test/a2a.test.ts`       | the card builds its OpenID Connect URL on the parsed origin                   | `a2a::the_card_builds_its_openid_connect_url_on_the_parsed_origin`                        |
| `test/a2a.test.ts`       | the card says plainly that it cannot approve                                  | `a2a::the_card_says_plainly_that_it_cannot_approve`                                       |
| `test/a2a.test.ts`       | a data part is read in preference to prose                                    | `a2a::a_data_part_is_read_in_preference_to_prose`                                         |
| `test/a2a.test.ts`       | owner/repo#number is understood                                               | `a2a::owner_repo_hash_number_is_understood`                                               |
| `test/a2a.test.ts`       | a looser sentence still resolves                                              | `a2a::a_looser_sentence_still_resolves`                                                   |
| `test/a2a.test.ts`       | a bare number is refused rather than guessed at                               | `a2a::a_bare_number_is_refused_rather_than_guessed_at`                                    |
| `test/a2a.test.ts`       | a data part naming a repo but no number is an error, not a guess              | `a2a::a_data_part_naming_a_repo_but_no_number_is_an_error_not_a_guess`                    |
| `test/a2a.test.ts`       | an empty message is refused                                                   | `a2a::an_empty_message_is_refused`                                                        |
| `test/a2a.test.ts`       | an unusable request is REJECTED, not FAILED                                   | `a2a::an_unusable_request_is_rejected_not_failed`                                         |
| `test/a2a.test.ts`       | a Task carries no `kind` field — 1.0 removed the discriminator                | `a2a::a_task_carries_no_kind_field_because_1_0_removed_the_discriminator`                 |
| `test/a2a.test.ts`       | a text part is { text }, not { kind, text }                                   | `a2a::a_text_part_is_text_not_kind_and_text`                                              |
| `test/a2a.test.ts`       | a caller-supplied contextId is preserved across the exchange                  | `a2a::a_caller_supplied_context_id_is_preserved_across_the_exchange`                      |
| `test/a2a.test.ts`       | a review that throws becomes a FAILED task, not a transport error             | `a2a::a_review_that_fails_becomes_a_failed_task_not_a_transport_error`                    |
| `test/a2a.test.ts`       | an unknown method is a JSON-RPC error that says what is served                | `a2a::an_unknown_method_is_a_json_rpc_error_that_says_what_is_served`                     |
| `test/a2a.test.ts`       | a pathological input does not hang the extractor                              | `a2a::a_pathological_input_does_not_hang_the_extractor`                                   |
| `test/a2a.test.ts`       | the near-miss shape is fast too                                               | `a2a::the_near_miss_shape_is_fast_too`                                                    |
| `test/a2a.test.ts`       | bounding the input did not break ordinary references                          | `a2a::bounding_the_input_did_not_break_ordinary_references`                               |
| `test/auth.test.ts`      | a correctly-scoped token is accepted                                          | `auth::a_correctly_scoped_token_is_accepted`                                              |
| `test/auth.test.ts`      | an unset WORKOS_ISSUER is refused, not skipped                                | `auth::an_unset_workos_issuer_is_refused_not_skipped`                                     |
| `test/auth.test.ts`      | an unset WORKOS_AUDIENCE is refused, not skipped                              | `auth::an_unset_workos_audience_is_refused_not_skipped`                                   |
| `test/auth.test.ts`      | a token minted for another MCP resource is refused                            | `auth::a_token_minted_for_another_mcp_resource_is_refused`                                |
| `test/auth.test.ts`      | a token from another issuer is refused                                        | `auth::a_token_from_another_issuer_is_refused`                                            |
| `test/auth.test.ts`      | a token from another organization is refused                                  | `auth::a_token_from_another_organization_is_refused`                                      |
| `test/auth.test.ts`      | an org member with neither the role nor the permission is refused             | `auth::an_org_member_with_neither_the_role_nor_the_permission_is_refused`                 |
| `test/auth.test.ts`      | the permission alone satisfies the gate                                       | `auth::the_permission_alone_satisfies_the_gate`                                           |
| `test/auth.test.ts`      | the retired mongodb:access permission no longer satisfies the gate            | `auth::the_retired_mongodb_access_permission_no_longer_satisfies_the_gate`                |
| `test/auth.test.ts`      | a member with an unrelated permission is refused                              | `auth::a_member_with_an_unrelated_permission_is_refused`                                  |
| `test/auth.test.ts`      | an expired token is refused                                                   | `auth::an_expired_token_is_refused`                                                       |
| `test/auth.test.ts`      | an unset WORKOS_JWKS_URL is refused                                           | `auth::an_unset_workos_jwks_url_is_refused`                                               |
| `test/auth.test.ts`      | an agent token is accepted on its scope claim                                 | `auth::an_agent_token_is_accepted_on_its_scope_claim`                                     |
| `test/auth.test.ts`      | scope is space-separated, not an array — all of it is read                    | `auth::scope_is_space_separated_not_an_array_and_all_of_it_is_read`                       |
| `test/auth.test.ts`      | an agent whose scope does not match is still refused                          | `auth::an_agent_whose_scope_does_not_match_is_still_refused`                              |
| `test/auth.test.ts`      | an agent from another organization is refused, as a person would be           | `auth::an_agent_from_another_organization_is_refused_as_a_person_would_be`                |
| `test/auth.test.ts`      | an agent holding only the retired mongodb:access scope is refused             | `auth::an_agent_holding_only_the_retired_mongodb_access_scope_is_refused`                 |
| `test/auth.test.ts`      | accepting scope does not let a person in without a role                       | `auth::accepting_scope_does_not_let_a_person_in_without_a_role`                           |
| `test/auth.test.ts`      | callerIdentity separates an agent from a person                               | `auth::caller_identity_separates_an_agent_from_a_person`                                  |
| `test/auth.test.ts`      | callerIdentity records who the agent acts for                                 | `auth::caller_identity_records_who_the_agent_acts_for`                                    |
| `test/auth.test.ts`      | a token for the served resource is accepted without a static audience         | `auth::a_token_for_the_served_resource_is_accepted_without_a_static_audience`             |
| `test/auth.test.ts`      | serving a resource does not widen the audience to other resources             | `auth::serving_a_resource_does_not_widen_the_audience_to_other_resources`                 |
| `test/der.test.ts`       | RSA-2048/3072/4096: wrapper output is byte-identical to real PKCS#8           | `der::wrapper_output_is_byte_identical_to_real_pkcs8_at_2048_3072_and_4096`               |
| `test/der.test.ts`       | RSA-2048/3072/4096: WebCrypto imports the wrapped key and signs               | `der::the_wrapped_key_imports_and_signs_at_every_size`                                    |
| `test/der.test.ts`       | pemBody distinguishes PKCS#1 from PKCS#8                                      | `der::pem_body_distinguishes_pkcs1_from_pkcs8`                                            |
| `test/der.test.ts`       | pemBody rejects a non-PEM value rather than producing a junk key              | `der::pem_body_rejects_a_non_pem_value_rather_than_producing_a_junk_key`                  |
| `test/der.test.ts`       | derLength uses short form below 128 and long form at or above it              | `der::der_length_uses_short_form_below_128_and_long_form_at_or_above_it`                  |
| `test/origin.test.ts`    | Origin validation allows the resource's own origin and refuses others         | `origin::origin_validation_allows_the_resources_own_origin_and_refuses_others`            |
| `test/origin.test.ts`    | an absent Origin is allowed                                                   | `origin::an_absent_origin_is_allowed`                                                     |
| `test/policy.test.ts`    | an allowlisted repo resolves to owner and name                                | `policy::an_allowlisted_repo_resolves_to_owner_and_name`                                  |
| `test/policy.test.ts`    | the allowlist is case-insensitive                                             | `policy::the_allowlist_is_case_insensitive`                                               |
| `test/policy.test.ts`    | a repo outside the allowlist is refused                                       | `policy::a_repo_outside_the_allowlist_is_refused`                                         |
| `test/policy.test.ts`    | an unset allowlist denies everything rather than allowing everything          | `policy::an_unset_allowlist_denies_everything_rather_than_allowing_everything`            |
| `test/policy.test.ts`    | a malformed slug is rejected before any call is made                          | `policy::a_malformed_slug_is_rejected_before_any_call_is_made`                            |
| `test/policy.test.ts`    | APPROVE is refused, in any casing                                             | `policy::approve_is_refused_in_any_casing`                                                |
| `test/policy.test.ts`    | an unrecognised review event is refused                                       | `policy::an_unrecognised_review_event_is_refused`                                         |
| `test/policy.test.ts`    | a permission the installation does not hold at all is missing                 | `policy::a_permission_the_installation_does_not_hold_at_all_is_missing`                   |
| `test/policy.test.ts`    | write satisfies a read request                                                | `policy::write_satisfies_a_read_request`                                                  |
| `test/policy.test.ts`    | read does not satisfy a write request                                         | `policy::read_does_not_satisfy_a_write_request`                                           |
| `test/policy.test.ts`    | an exact match is not missing                                                 | `policy::an_exact_match_is_not_missing`                                                   |
| `test/policy.test.ts`    | extra permissions the installation holds are not reported                     | `policy::extra_permissions_the_installation_holds_are_not_reported`                       |
| `test/policy.test.ts`    | an empty installation misses everything requested                             | `policy::an_empty_installation_misses_everything_requested`                               |
| `test/policy.test.ts`    | the metadata advertises no scopes                                             | `policy::the_metadata_advertises_no_scopes`                                               |
| `test/policy.test.ts`    | resource metadata fails closed when WORKOS_AUTHORIZATION_SERVER is unset      | `policy::resource_metadata_fails_closed_when_workos_authorization_server_is_unset`        |
| `test/policy.test.ts`    | the advertised authorization server is parsed into an https origin            | `policy::the_advertised_authorization_server_is_parsed_into_an_https_origin`              |
| `test/policy.test.ts`    | every tool carries a full set of annotations                                  | `policy::every_tool_carries_a_full_set_of_annotations`                                    |
| `test/policy.test.ts`    | the read tools are the ones that read, and nothing else                       | `policy::the_read_tools_are_the_ones_that_read_and_nothing_else`                          |
| `test/policy.test.ts`    | no read-only tool is marked destructive, and no writer is marked read-only    | `policy::no_read_only_tool_is_marked_destructive_and_only_the_two_updates_are`            |
| `test/policy.test.ts`    | tools/list advertises the annotations, not just the schema                    | `policy::every_tool_carries_a_full_set_of_annotations`                                    |
| `test/policy.test.ts`    | paginate reports another page only when one exists                            | `policy::paginate_reports_another_page_only_when_one_exists`                              |
| `test/policy.test.ts`    | paginate carries the page number through                                      | `policy::paginate_carries_the_page_number_through`                                        |
| `test/policy.test.ts`    | slimPull keeps what a reviewer needs and drops the rest                       | `policy::slim_pull_keeps_what_a_reviewer_needs_and_drops_the_rest`                        |
| `test/policy.test.ts`    | slimIssue flags pull requests returned by the issues endpoint                 | `policy::slim_issue_flags_pull_requests_returned_by_the_issues_endpoint`                  |
| `test/policy.test.ts`    | a GitHubError reaches the caller — it is the actionable one                   | `policy::a_github_error_reaches_the_caller_because_it_is_the_actionable_one`              |
| `test/policy.test.ts`    | any other throw does not, however tempting the message                        | `policy::any_other_failure_does_not_however_tempting_the_message`                         |
| `test/policy.test.ts`    | a thrown non-Error is not stringified into the response either                | `policy::an_internal_failure_carrying_a_token_is_not_stringified_into_the_response`       |
| `test/policy.test.ts`    | an argument error names the field so the caller can fix the call              | `policy::an_argument_error_names_the_field_so_the_caller_can_fix_the_call`                |
| `test/policy.test.ts`    | a bad argument reaches the caller through tools/call, not a stub              | `transport::a_bad_argument_reaches_the_caller_through_tools_call_not_a_stub`              |
| `test/resource.test.ts`  | metadata on host × path names the served origin                               | `resource::metadata_names_the_served_origin_on_every_host_and_path`                       |
| `test/resource.test.ts`  | a mistyped MCP_RESOURCE_URL cannot leak into an allowed host's metadata       | `resource::a_mistyped_mcp_resource_url_cannot_leak_into_an_allowed_hosts_metadata`        |
| `test/resource.test.ts`  | the workers.dev preview names itself                                          | `resource::the_workers_dev_preview_names_itself`                                          |
| `test/resource.test.ts`  | an unknown Host is never reflected; the canonical URL is used                 | `resource::an_unknown_host_is_never_reflected_and_the_canonical_url_is_used`              |
| `test/resource.test.ts`  | hosts are matched case-insensitively and the canonical host is always allowed | `resource::hosts_are_matched_case_insensitively_and_the_canonical_host_is_always_allowed` |
| `test/resource.test.ts`  | the 401 challenge points at the served host's metadata                        | `resource::the_401_challenge_points_at_the_served_hosts_metadata`                         |
| `test/resource.test.ts`  | the committed wrangler.toml names only real hosts                             | `resource::the_committed_wrangler_toml_names_only_real_hosts`                             |
| `test/review.test.ts`    | annotateDiff numbers added lines from the hunk header                         | `review::annotate_diff_numbers_added_lines_from_the_hunk_header`                          |
| `test/review.test.ts`    | a removed line never becomes a comment target                                 | `review::a_removed_line_never_becomes_a_comment_target`                                   |
| `test/review.test.ts`    | context lines advance the counter but are not targets                         | `review::context_lines_advance_the_counter_but_are_not_targets`                           |
| `test/review.test.ts`    | a new file numbers from 1                                                     | `review::a_new_file_numbers_from_1`                                                       |
| `test/review.test.ts`    | a rename attributes added lines to the new path, not the old                  | `review::a_rename_attributes_added_lines_to_the_new_path_not_the_old`                     |
| `test/review.test.ts`    | several hunks in one file each restart from their own header                  | `review::several_hunks_in_one_file_each_restart_from_their_own_header`                    |
| `test/review.test.ts`    | two files do not share a line-number space                                    | `review::two_files_do_not_share_a_line_number_space`                                      |
| `test/review.test.ts`    | a binary file is noted, not numbered                                          | `review::a_binary_file_is_noted_not_numbered`                                             |
| `test/review.test.ts`    | a finding on a line the diff does not add is held back, not posted            | `review::a_finding_on_a_line_the_diff_does_not_add_is_held_back_not_posted`               |
| `test/review.test.ts`    | findings are ranked so a cap keeps the serious ones                           | `review::findings_are_ranked_so_a_cap_keeps_the_serious_ones`                             |
| `test/review.test.ts`    | a JSON string response is parsed, an object response is taken as is           | `review::a_json_string_response_is_parsed_an_object_response_is_taken_as_is`              |
| `test/review.test.ts`    | malformed findings are dropped individually, not fatally                      | `review::malformed_findings_are_dropped_individually_not_fatally`                         |
| `test/review.test.ts`    | an unknown severity degrades to note rather than throwing                     | `review::an_unknown_severity_degrades_to_note_rather_than_failing`                        |
| `test/review.test.ts`    | a model that returns prose instead of JSON fails loudly                       | `review::a_model_that_returns_prose_instead_of_json_fails_loudly`                         |
| `test/review.test.ts`    | a missing findings array is an empty review, not a crash                      | `review::a_missing_findings_array_is_an_empty_review_not_a_crash`                         |
| `test/review.test.ts`    | unanchored findings appear in the body instead of vanishing                   | `review::unanchored_findings_appear_in_the_body_instead_of_vanishing`                     |
| `test/review.test.ts`    | the body says the reviewer cannot approve                                     | `review::the_body_says_the_reviewer_cannot_approve`                                       |
| `test/review.test.ts`    | truncation is disclosed, because a partial read is not a clean review         | `review::truncation_is_disclosed_because_a_partial_read_is_not_a_clean_review`            |
| `test/review.test.ts`    | truncate cuts on a line boundary                                              | `review::truncate_cuts_on_a_line_boundary`                                                |
| `test/review.test.ts`    | text within budget is returned untouched                                      | `review::text_within_budget_is_returned_untouched`                                        |
| `test/review.test.ts`    | the kill switch fails closed before any model call                            | `review::the_kill_switch_fails_closed_before_any_model_call`                              |
| `test/review.test.ts`    | a missing AI binding says what to add rather than throwing on undefined       | `review::a_missing_ai_binding_says_what_to_add_rather_than_failing_obscurely`             |
| `test/review.test.ts`    | gateway metadata attributes cost without naming a person                      | `review::gateway_metadata_attributes_cost_without_naming_a_person`                        |
| `test/review.test.ts`    | no gateway configured means calling Workers AI directly                       | `review::no_gateway_configured_means_calling_workers_ai_directly`                         |
| `test/review.test.ts`    | asking to post without a head sha fails before the model is paid              | `review::asking_to_post_without_a_head_sha_fails_before_the_model_is_paid`                |
| `test/review.test.ts`    | a dynamic route gets the OpenAI response_format and answer shape              | `review::a_dynamic_route_gets_the_openai_response_format_and_answer_shape`                |
| `test/setup.test.ts`     | the manifest redirect shows the convert command for a valid code              | `setup::the_manifest_redirect_shows_the_convert_command_for_a_valid_code`                 |
| `test/setup.test.ts`     | an invalid code is never echoed                                               | `setup::an_invalid_code_is_never_echoed`                                                  |
| `test/setup.test.ts`     | the post-install page is served                                               | `setup::the_post_install_page_is_served`                                                  |
| `test/setup.test.ts`     | the app manifest is least-privilege and on the canonical host                 | `setup::the_app_manifest_is_least_privilege_and_on_the_canonical_host`                    |
| `test/setup.test.ts`     | the one-click page posts the bundled manifest to the shamwari-ai org          | `setup::the_one_click_page_posts_the_bundled_manifest_to_the_bundu_labs_enterprise`       |
| `test/transport.test.ts` | GET and DELETE on the MCP endpoint are 405                                    | `transport::get_and_delete_on_the_mcp_endpoint_are_405`                                   |
| `test/transport.test.ts` | a foreign Origin is refused with 403                                          | `transport::a_foreign_origin_is_refused_with_403`                                         |
| `test/transport.test.ts` | the resource's own Origin is allowed                                          | `transport::the_resources_own_origin_is_allowed`                                          |
| `test/transport.test.ts` | server/discover returns supported versions, capabilities and identity         | `transport::server_discover_returns_supported_versions_capabilities_and_identity`         |
| `test/transport.test.ts` | an unknown method is 404, not 200                                             | `transport::an_unknown_method_is_404_not_200`                                             |
| `test/transport.test.ts` | a missing Mcp-Method header is 400 with HeaderMismatch                        | `transport::a_missing_mcp_method_header_is_400_with_header_mismatch`                      |
| `test/transport.test.ts` | an unsupported version is 400 with the supported list                         | `transport::an_unsupported_version_is_400_with_the_supported_list`                        |
| `test/transport.test.ts` | tools/list works on the modern path                                           | `transport::tools_list_works_on_the_modern_path`                                          |
| `test/transport.test.ts` | initialize still answers with the legacy revision                             | `transport::initialize_still_answers_with_the_legacy_revision`                            |
| `test/transport.test.ts` | a legacy request carries no headers and is not version-validated              | `transport::a_legacy_request_carries_no_headers_and_is_not_version_validated`             |
| `test/transport.test.ts` | an unknown method stays 200 for a legacy client                               | `transport::an_unknown_method_stays_200_for_a_legacy_client`                              |
| `test/transport.test.ts` | no bearer token is still 401, whatever the era                                | `transport::no_bearer_token_is_still_401_whatever_the_era`                                |
| `test/transport.test.ts` | an unexpected error is logged, not returned                                   | `transport::an_unexpected_error_is_logged_not_returned`                                   |
| `test/transport.test.ts` | a GitHubError message is returned, because it is written for the caller       | `transport::a_github_error_message_is_returned_because_it_is_written_for_the_caller`      |
| `test/webhook.test.ts`   | a draft pull request is not reviewed                                          | `webhook::a_draft_pull_request_is_not_reviewed`                                           |
| `test/webhook.test.ts`   | a draft is skipped on every action, not only on synchronize                   | `webhook::a_draft_is_skipped_on_every_action_not_only_on_synchronize`                     |
| `test/webhook.test.ts`   | leaving draft reviews the WHOLE pull request, not just the last push          | `webhook::leaving_draft_reviews_the_whole_pull_request_not_just_the_last_push`            |
| `test/webhook.test.ts`   | a push onto an open, non-draft pull request reviews that push                 | `webhook::a_push_onto_an_open_non_draft_pull_request_reviews_that_push`                   |
| `test/webhook.test.ts`   | opening a ready pull request reviews the whole thing                          | `webhook::opening_a_ready_pull_request_reviews_the_whole_thing`                           |
| `test/webhook.test.ts`   | an all-zero before sha falls back to the full diff                            | `webhook::an_all_zero_before_sha_falls_back_to_the_full_diff`                             |
| `test/webhook.test.ts`   | a closed pull request is not reviewed on a late delivery                      | `webhook::a_closed_pull_request_is_not_reviewed_on_a_late_delivery`                       |
| `test/webhook.test.ts`   | actions that are not a new commit are ignored                                 | `webhook::actions_that_are_not_a_new_commit_are_ignored`                                  |
| `test/webhook.test.ts`   | other event types are ignored, including a bare push                          | `webhook::other_event_types_are_ignored_including_a_bare_push`                            |
| `test/webhook.test.ts`   | a ping is skipped without looking like a failure                              | `webhook::a_ping_is_skipped_without_looking_like_a_failure`                               |
| `test/webhook.test.ts`   | a payload missing what a review needs is skipped, not guessed at              | `webhook::a_payload_missing_what_a_review_needs_is_skipped_not_guessed_at`                |
| `test/webhook.test.ts`   | a garbage payload does not throw                                              | `webhook::a_garbage_payload_does_not_panic`                                               |
| `test/webhook.test.ts`   | a correctly signed body verifies                                              | `webhook::a_correctly_signed_body_verifies`                                               |
| `test/webhook.test.ts`   | a body altered after signing does not                                         | `webhook::a_body_altered_after_signing_does_not`                                          |
| `test/webhook.test.ts`   | a signature from a different secret does not                                  | `webhook::a_signature_from_a_different_secret_does_not`                                   |
| `test/webhook.test.ts`   | a missing or malformed signature header does not                              | `webhook::a_missing_or_malformed_signature_header_does_not`                               |
| `test/webhook.test.ts`   | an unset secret never verifies, whatever is presented                         | `webhook::an_unset_secret_never_verifies_whatever_is_presented`                           |
| `test/webhook.test.ts`   | a mention from a maintainer summons a review                                  | `webhook::a_mention_from_a_maintainer_summons_a_review`                                   |
| `test/webhook.test.ts`   | a bot's comment NEVER summons a review, even saying the handle                | `webhook::a_bots_comment_never_summons_a_review_even_saying_the_handle`                   |
| `test/webhook.test.ts`   | a commenter without write access cannot spend a review                        | `webhook::a_commenter_without_write_access_cannot_spend_a_review`                         |
| `test/webhook.test.ts`   | OWNER, MEMBER and COLLABORATOR all may                                        | `webhook::owner_member_and_collaborator_all_may`                                          |
| `test/webhook.test.ts`   | a comment without the handle is ignored                                       | `webhook::a_comment_without_the_handle_is_ignored`                                        |
| `test/webhook.test.ts`   | a comment on an issue is not a pull request review                            | `webhook::a_comment_on_an_issue_is_not_a_pull_request_review`                             |
| `test/webhook.test.ts`   | only a newly created comment triggers, never an edit                          | `webhook::only_a_newly_created_comment_triggers_never_an_edit`                            |
| `test/webhook.test.ts`   | the handle matches as a word, not as a substring                              | `webhook::the_handle_matches_as_a_word_not_as_a_substring`                                |
| `test/webhook.test.ts`   | the handle is configurable, because the brand is                              | `webhook::the_handle_is_configurable_because_the_brand_is`                                |

### Tests with no TypeScript original

Added with the port, mostly end-to-end coverage the TypeScript suite did not
have (it never ran the review engine, the token mint or the webhook HTTP
handler against a stand-in GitHub).

| Rust test                                                                                    |
| -------------------------------------------------------------------------------------------- |
| `a2a::a_completed_review_carries_its_result_inline_as_a_data_part`                           |
| `auth::a_token_not_yet_valid_is_refused`                                                     |
| `auth::a_tampered_payload_fails_signature_verification`                                      |
| `auth::a_non_rs256_token_and_a_malformed_token_are_refused`                                  |
| `auth::the_jwks_is_cached_between_verifications`                                             |
| `policy::approve_is_refused_even_for_a_repo_that_is_not_allowlisted`                         |
| `policy::there_is_no_approve_tool_and_no_merge_tool`                                         |
| `policy::the_tool_names_are_exactly_the_ones_the_typescript_server_exposed`                  |
| `review::the_annotated_text_is_exactly_what_the_model_is_shown`                              |
| `review::a_line_given_as_a_numeric_string_is_accepted_as_javascript_number_did`              |
| `review::a_non_object_response_fails_loudly`                                                 |
| `review::the_body_carries_the_marker_that_makes_a_second_run_detectable`                     |
| `review::truncate_never_splits_a_multibyte_character`                                        |
| `review::a_dry_run_reviews_without_posting_and_passes_the_gateway_as_the_third_argument`     |
| `review::posting_writes_one_commit_comment_never_a_pull_request_review`                      |
| `review::a_commit_that_already_carries_a_review_is_skipped_before_the_model_is_paid`         |
| `review::an_oversized_diff_is_truncated_and_says_so`                                         |
| `review::the_installation_token_asks_for_the_scoped_permissions_and_one_repository`          |
| `review::the_app_jwt_is_signed_with_the_configured_key_and_backdated`                        |
| `review::the_app_id_and_key_must_both_be_present`                                            |
| `review::a_pkcs1_pem_from_github_works_as_it_is_downloaded`                                  |
| `setup::the_manifest_never_asks_for_workflows_administration_or_contents_write`              |
| `setup::each_new_page_load_carries_a_fresh_state`                                            |
| `transport::a_missing_protocol_version_header_is_400_with_header_mismatch`                   |
| `transport::a_header_that_disagrees_with_the_body_is_400_with_header_mismatch`               |
| `transport::tools_call_requires_the_mcp_name_header_to_match_the_tool`                       |
| `transport::a_modern_header_without_the_envelope_is_400_invalid_params`                      |
| `transport::an_envelope_missing_client_capabilities_is_400_invalid_params`                   |
| `transport::an_unknown_legacy_protocol_version_is_answered_with_the_latest_supported`        |
| `transport::a_legacy_notification_is_accepted_with_202_and_no_body`                          |
| `transport::a_legacy_batch_is_answered_as_a_batch`                                           |
| `transport::a_batch_may_not_carry_a_modern_envelope`                                         |
| `transport::a_non_json_content_type_is_415_and_invalid_json_is_400`                          |
| `transport::a_body_that_is_not_json_rpc_is_400_invalid_request`                              |
| `transport::a_rejected_token_is_401_invalid_token_naming_the_gate_but_not_the_token`         |
| `transport::the_a2a_endpoint_is_behind_the_same_gate`                                        |
| `transport::health_the_agent_card_and_unknown_paths`                                         |
| `transport::a_missing_required_argument_names_the_field`                                     |
| `transport::an_unknown_tool_is_an_invalid_params_error`                                      |
| `transport::a_repo_outside_the_allowlist_is_refused_through_tools_call_before_any_request`   |
| `transport::defaults_are_applied_and_the_list_query_is_what_github_expects`                  |
| `transport::an_update_with_nothing_to_change_is_an_argument_error`                           |
| `transport::a_create_review_with_approve_is_rejected_by_the_schema_before_it_reaches_github` |
| `transport::the_input_schemas_follow_the_zod_ones_required_fields_and_defaults`              |
| `webhook::a_known_vector_matches_githubs_documented_example`                                 |
| `webhook::an_unconfigured_webhook_answers_503_not_200`                                       |
| `webhook::an_unsigned_or_badly_signed_delivery_is_401_and_runs_nothing`                      |
| `webhook::a_signed_non_json_body_is_400_and_get_is_405`                                      |
| `webhook::a_signed_pull_request_delivery_is_queued_with_202`                                 |
| `webhook::a_repository_outside_the_allowlist_is_skipped_before_anything_is_spent`            |
| `webhook::a_draft_delivery_is_acknowledged_but_not_queued`                                   |
| `webhook::the_trigger_associations_are_configurable`                                         |
| `webhook::a_mention_on_a_closed_pull_request_is_skipped`                                     |

## What differs, and what cannot be preserved

Nothing below weakens a security property in the contract; each is a
difference in mechanism or wording.

1. **MCP is hand-written, not the SDK.** The TypeScript used
   `@modelcontextprotocol/server` 2.4 (`createMcpHandler`). There is no Rust MCP
   crate that targets Workers wasm and both protocol eras, so `src/mcp.rs`
   implements the stateless binding itself, reading the SDK's classifier as the
   reference for era detection, the `-32020` / `-32022` / `-32602` rejections,
   the HTTP statuses and the `_meta` envelope. Not reproduced, because this
   server never used them: `subscriptions/listen`, resources, prompts,
   completion, input-required rounds, the request-body size limit (Workers
   enforces its own), and the exact text of SDK error messages. Argument
   validation messages are worded differently from Zod's (`field: Invalid
input: expected number, received string`), still naming the field, still an
   `isError` tool result.
2. **Legacy replies are plain JSON.** The SDK answered legacy `POST`s that
   accepted `text/event-stream` as one SSE message. Plain
   `application/json` is valid for the same requests under the Streamable HTTP
   spec; the Rust server never streams, because no tool does.
3. **RSA is the `rsa` crate, not WebCrypto.** One tested code path (host and
   wasm) instead of two. RS256 signing and verification are RSASSA-PKCS1-v1_5,
   which the `rsa` crate (0.10) gates behind its `pkcs1v15` feature and
   documents as legacy: it is required here (GitHub issues RS256 App JWTs and
   WorkOS signs RS256), and the Worker never decrypts anything. The crate's
   constant-time hardening is still in progress upstream; the private key never
   leaves the isolate and signing inputs are not attacker-chosen. RSA signing
   in wasm costs CPU time that WebCrypto did not: the parsed key and installation
   tokens are cached per isolate to keep it to once per token lifetime.
4. **Tracing is real, with a newer local toolchain.** The spans are the same
   (`invoke_agent` with a nested `chat`, metadata only) and are opened with
   `worker::observability`. `workers-rs` 0.9 wraps every handler in the
   `cloudflare:workers` `tracing` export, so local `wrangler dev` needs a
   current wrangler 4.x (4.87 fails; 4.166 passes). Production already has it.
5. **`truncate` counts bytes**, not UTF-16 code units, on a character boundary.
   The default budget is "200,000 bytes" either way.
6. **`/github-app/new` posts to the enterprise**
   (`https://github.com/enterprises/bundu-labs/settings/apps/new`), not the
   `shamwari-ai` organisation. GitHub documents the manifest flow for personal
   and organisation accounts only, so the runbook also has a manual path.
7. **Dates are parsed by hand** (RFC 3339 `expires_at`), not `Date.parse`; an
   unparseable value means "do not cache" in both.
8. **`preview_urls` is off** in `wrangler.toml`: the preview-version upload
   from `staging` no longer exists.
9. **The test key is generated in memory** each run. No private key, even a
   throwaway one, is committed.

## Verification

Run on the branch that introduced this page:

| Check                                                   | Result                                                            |
| ------------------------------------------------------- | ----------------------------------------------------------------- |
| `cargo fmt --check`                                     | clean                                                             |
| `cargo clippy --all-targets -- -D warnings`             | clean, host and `wasm32-unknown-unknown`                          |
| `cargo test`                                            | 210 passed                                                        |
| `cargo build --target wasm32-unknown-unknown --release` | builds                                                            |
| `worker-build --release`                                | builds (via `wrangler`'s `[build]`)                               |
| `wrangler deploy --dry-run`                             | OK: 1706 KiB, 603 KiB gzipped; bindings as before; needs no login |
| `scripts/smoke-local.sh` (wasm on workerd)              | 19 checks passed                                                  |

`scripts/smoke-local.sh` runs the built Worker under `wrangler dev` with
throwaway keys and a stand-in GitHub API: the MCP round trip in both eras,
WorkOS token verification against a local JWKS, the webhook signature path
(good, wrong, missing), and an App JWT signed in wasm and then verified with
`openssl`. It needs no Cloudflare login and touches nothing real. On workerd
the first `shamwari_whoami` (parse the key, sign the App JWT in wasm, four calls
to the stand-in API) took 37 ms wall clock.
