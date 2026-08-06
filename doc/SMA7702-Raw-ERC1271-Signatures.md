# SMA7702 Raw EOA ERC-1271 Signatures

## Purpose and scope

Some applications dispatch exclusively on whether a signer has code. An EIP-7702 delegated EOA has code while
retaining its private key, and its wallet may produce a plain EOA signature without knowing that the address is
delegated. Permit2 is a concrete example of an integration that routes this signature through ERC-1271.

For compatibility with these integrations, `SemiModularAccount7702.isValidSignature(bytes32,bytes)` accepts
canonical 65-byte ECDSA and 64-byte ERC-2098 signatures directly over its caller-supplied digest.

Raw recovery must equal `address(this)`, the delegating EOA. This is another encoding for the already-root EOA key,
not a new signer or authority path.

A verifier does not depend on this path for signature formats that it successfully recovers as ECDSA before trying
ERC-1271. Which formats those are differs by library and by version, and it determines whether deactivating raw
mode has any effect on that verifier. See [What deactivation does not reach](#what-deactivation-does-not-reach).

The bare-length dispatcher exists only in the public ERC-1271 function:

- Fallback runtime validation retains its validation locator and authorization framing and authenticates
  `msg.sender`.
- Fallback UserOperation validation retains its outer signature framing, selector checks, pre-validation hooks,
  fallback signer checks, and UserOperation digest.
- Deferred actions retain their envelope, selector checks, fallback signer checks, and account-scoped digest. A
  selected validation with pre-validation hooks remains ineligible.

## Activation and outcomes

**Raw mode is active by default.** A newly delegated, otherwise unconfigured SMA7702 has fallback signing enabled,
resolves its zero-valued stored fallback signer to `address(this)`, and has no hooks on native fallback validation.
Raw mode remains active only while all three conditions hold:

1. Fallback signing is enabled.
2. The resolved fallback signer is the delegated EOA itself (`address(this)`).
3. Native `FALLBACK_VALIDATION` has no associated pre-validation hooks.

Wallets and SDKs choosing an encoding can inspect the first two conditions with `getFallbackSignerData()` and the
third with `getValidationData(FALLBACK_VALIDATION).validationHooks.length`. This state is mutable, so the encoding
must reflect the account's current configuration.

| Raw-mode state | Signature length | `isValidSignature(hash, signature)` behavior |
| --- | --- | --- |
| Active | 64 or 65 | Treats the entire value exclusively as bare ECDSA over `hash`; returns `0x1626ba7e` only for canonical recovery to `address(this)`, otherwise `0xffffffff`. This branch does not revert. |
| Active | Any other length | Uses standard modular decoding; valid configured signatures may succeed, while malformed inputs may return failure or revert. |
| Inactive | Any length, including 64 or 65 | Uses standard modular decoding; valid configured signatures may succeed, while bare or malformed inputs may return failure or revert depending on their bytes and account configuration. |

## Deactivating raw mode

There is deliberately no separate raw-signature setting. The EOA key can still authorize direct transactions and
change its EIP-7702 delegation, so another account flag would not be a security boundary against that key.

Each option below disables bare-signature compatibility. A codesize-only ERC-1271 caller that continues to submit
a bare signature is routed into modular decoding and may revert.

Raw mode can be deactivated in three ways, with different consequences:

1. Install a pre-validation hook on native `FALLBACK_VALIDATION`. This retains fallback signing but routes 64- and
   65-byte inputs through standard modular validation, so codesize-only ERC-1271 callers submitting a bare
   signature may receive a revert instead of a valid-signature result. The hook runs on fallback
   `executeWithRuntimeValidation`, UserOperation, and ERC-1271 validation and makes fallback validation ineligible
   for deferred actions under the existing no-validation-hooks rule. A purpose-built no-op hook must implement
   all three `IValidationHookModule` pre-validation entry points. Install it on the zero-module/entity
   `FALLBACK_VALIDATION` key with empty validation-level install data. Sparse per-hook segments are omitted when
   their data is empty; standard signatures still use their existing `0xff` final validation segment.
2. Call `updateFallbackSignerData(otherSigner, false)`. This moves fallback authority to `otherSigner`, and the
   delegated EOA can no longer validate UserOperations or runtime calls through native fallback validation.
3. Call `updateFallbackSignerData(anySigner, true)`. This disables fallback signing entirely. Native fallback
   UserOperation, runtime, and ERC-1271 validation then revert with `FallbackSignerDisabled`. Direct top-level
   transactions from the delegated EOA and public account functions remain available.

A native fallback validation hook does not constrain the delegated EOA itself. A top-level transaction from the
EOA has `msg.sender == address(this)` and bypasses validation and validation-associated hooks.
Selector-associated execution hooks still run.

A hook constrains ERC-1271 only if its `preSignatureValidationHook` enforces a constraint; the bundled permission
modules implement that hook as a no-op.

Calling `uninstallValidation(FALLBACK_VALIDATION, ...)` does not remove native fallback validation or change
`fallbackSigner` or `fallbackSignerDisabled`. It clears the flags, selectors, pre-validation hooks, and
validation-associated execution hooks stored under that validation key. Removing all pre-validation hooks can
make raw mode eligible again, but only if fallback signing is enabled and the resolved signer is `address(this)`.
Reinstalling such a hook disables it again. The hook opt-out is therefore reversible configuration, not signature
revocation. It is also not universal; see [Why no contract change can fix this](#why-no-contract-change-can-fix-this).

Execution hooks, hooks on the fallback direct-call key or another validation, and the fallback validation's
`isGlobal`, `isSignatureValidation`, and `isUserOpValidation` flags do not control raw mode. Those flags are inert
for native fallback validation generally: the SMA fallback paths short-circuit the standard flag checks and treat
the fallback as global.

On SMA7702, `updateFallbackSignerData(address(0), false)` restores `address(this)` as the effective fallback
signer; it does not disable anything.

## What deactivation does not reach

This section is only about the deactivated case: what happens to an already-issued bare signature after one of the
three opt-outs above is applied. While raw mode is active, every consumer that reaches `isValidSignature` accepts a
canonical bare signature, and there is nothing further to say.

Deactivating raw mode is not universal. It only affects consumers that actually call the account. An ECDSA-first
verifier recovers the signature and compares the result against the expected signer without calling the account at
all, so no account configuration changes that outcome, because no account code runs.

The table below shows consumer behavior after a pre-validation hook is installed on native `FALLBACK_VALIDATION`,
deactivating raw mode while the signing key is unchanged.

| Consumer | 64-byte ERC-2098 | 65-byte ECDSA |
| --- | --- | --- |
| OpenZeppelin `SignatureChecker.isValidSignatureNow` (v5.0.2, `lib/openzeppelin-contracts`) | Falls through to ERC-1271, rejected | Recovered directly, remains valid |
| Solady `SignatureCheckerLib.isValidSignatureNow` (v0.0.237, `node_modules/solady`) | Recovered directly, remains valid | Recovered directly, remains valid |
| Code-first verifier, dispatching on `signer.code.length` | Sent to ERC-1271, rejected by revert | Sent to ERC-1271, rejected by revert |
| Direct ERC-1271 caller, including Permit2 | Rejected by revert | Rejected by revert |

"Rejected by revert" is not the same as a clean `0xffffffff`. Once raw mode is off, a bare 64- or 65-byte value is
parsed as a modular signature and reverts with `ValidationSignatureSegmentMissing`. A verifier that wraps the call
and maps failure to `false` sees a plain rejection. One that calls the account directly and propagates the
revert — Permit2 among them — surfaces it to its own caller as a failed transaction or a failed gas estimate.

OpenZeppelin's `isValidSignatureNow` attempts ECDSA recovery before ERC-1271, but its bytes-based
`ECDSA.tryRecover` handles only 65-byte input and reports `InvalidSignatureLength` for the compact form. That single
asymmetry produces the split in the first row. Solady's equivalent attempts `ecrecover` for both lengths before
falling back to ERC-1271, so neither length reaches the account.

This is a property of the deployed verifier, not of the library name. Dispatch order has changed across releases of
both libraries. Check the version an integration actually deploys rather than assuming every `SignatureChecker`
behaves alike.

Deactivation also does not reach a result a consumer has already cached. A positive result cached before a hook
install or signer rotation stays positive, and execution driven only by that cache accepts a decision the account
would now reject. Validate at the point of use; if caching is unavoidable, bind the entry to an exact block or state
context.

### Why no contract change can fix this

A hook on native fallback validation is an ERC-1271 mode switch. So is rotating or disabling the fallback signer.
Neither revokes the EOA signature, and neither can restrict top-level transactions sent by the delegated EOA.

This follows from EIP-7702 rather than from anything specific to this implementation. The delegating key remains
root authority over the account: it can send top-level transactions that bypass validation entirely, and it can
sign a new EIP-7702 authorization that replaces the delegation. A signature produced by that key is not revocable
by account state, and no account bytecode is reachable when a verifier recovers the key directly. No contract-level
control can change that.

Where a bare signature must actually be revoked, use the consuming application's own controls, such as nonce
invalidation or deadline expiry. See [Replay and migration](#replay-and-migration).

### Calling convention and failure modes

In raw mode, both `STATICCALL` and `CALL` return a canonical 32-byte ABI-encoded `bytes4`. Prefer `STATICCALL`,
which enforces that validation cannot write state.

While raw mode is active the bare branch never reverts; a malformed, non-canonical, or non-matching 64- or 65-byte
value returns `0xffffffff`. When raw mode is inactive the same bytes enter modular decoding and may revert instead.
Consumers that map a failed ERC-1271 call to `false` handle both cases cleanly. Consumers that propagate the revert
turn an invalid signature into an application-level revert or a gas-estimation failure.

A caller-imposed gas cap below the cost of validation produces a false negative. Forward enough gas rather than
relying on a narrow measured threshold.

## Signature encoding

While raw mode is active, every 64- or 65-byte signature passed to `isValidSignature` is interpreted exclusively
as bare ECDSA. An invalid value returns the ERC-1271 failure value rather than falling through to modular decoding.
Recovery uses OpenZeppelin `ECDSA.tryRecover`, which requires canonical low-`s` values in both formats. The 65-byte
form also requires `v` equal to 27 or 28; the 64-byte form uses ERC-2098 compact encoding.

A standard modular signature must not total 64 or 65 bytes while raw mode is active. Its total length is:

`locatorPrefix + sum(5 + hookData.length) + 1 + moduleSignature.length`

`locatorPrefix` is 5 bytes for an entity locator or 21 bytes for a direct-call locator. Every supplied sparse hook
segment adds five framing bytes plus its non-empty data; omit the segment when hook data is empty. The additional
byte is the required `0xff` final-segment marker.

With no hook data, module signatures of 58 or 59 bytes for an entity locator, or 42 or 43 bytes for a direct-call
locator, collide with raw mode. The module is not called; raw ECDSA recovery alone determines the result, normally
returning `0xffffffff` without a module-specific diagnostic.

When raw mode is inactive, 64- and 65-byte inputs use standard modular decoding like every other length. A bare
ECDSA signature is not a valid modular encoding, and this path may revert rather than return `0xffffffff`
depending on the decoded bytes and installed validations. Valid modular signatures of those total lengths
continue to route normally.

The supported built-in formats do not collide. A `SingleSignerValidationModule` EOA payload produces a 72-byte
entity-locator ERC-1271 signature, and WebAuthn signatures are larger. A custom variable-length validation module
can still produce a complete 64- or 65-byte encoding. `ValidationLocatorLib.packSignature` does not reject these
totals, so avoiding the collision is the module's responsibility: pad or otherwise alter the encoding while raw
mode is active. Custom validation modules should document the signature lengths they can produce and how they avoid
these two. SDKs that assemble modular signatures should warn when they generate either total for an SMA7702.

## Other validation paths

Runtime, UserOperation, and deferred-action validation do not add bare-signature dispatch. Fallback runtime
validation authenticates `msg.sender` and has no `EOA` or `CONTRACT_OWNER` signature type.

In fallback UserOperation, standard modular ERC-1271, and deferred-action signature encodings,
`CONTRACT_OWNER` is rejected when native `FALLBACK_VALIDATION` resolves to `address(this)`; use `EOA` for the
delegated key. This prevents self-ERC-1271 recursion from promoting a signature-only validation to fallback-global
authority.

The shared `SemiModularAccountBase` guard blocks direct native-fallback self-reference in all three SMA variants.
`CONTRACT_OWNER` remains supported when the resolved fallback signer is a distinct contract.

## Replay and migration

The raw ERC-1271 digest is not wrapped with the account's replay-safe domain. The account adds no chain- or
account-scoped domain of its own, so all binding comes from the digest supplied by the calling application. This
matches ordinary EOA semantics.

The consuming application must bind the digest to the intended chain, verifying contract, signer, action, amount,
nonce, deadline, and any protocol-specific context. Where an application separates its digests poorly, the same
signature may be actionable in another context. That risk is not specific to delegated accounts or to ERC-1271;
this path accepts the approval that the EOA key already produced.

A canonical bare signature can validate later, once raw mode is active, if the application's own nonce, deadline,
and revocation state still permit the action. This applies to a signature created:

- before delegation;
- while raw mode was inactive;
- before the delegated code was replaced; or
- under an earlier implementation that did not accept bare ERC-1271 signatures.

Re-delegating an existing SMA7702 v1.0.0 EOA to v1.1.0 activates raw mode if the three gates above are satisfied. A
still-live bare approval that a codesize-only verifier rejected solely because v1.0.0 lacked this path can then
validate. Before any migration that activates bare-signature compatibility, invalidate any live application
approval that should not survive it, using the application's nonce or revocation controls including blanket
invalidation where supported. Alternatively, configure the account so that raw mode stays inactive.

The other SMA variants do not implement bare-signature dispatch.
