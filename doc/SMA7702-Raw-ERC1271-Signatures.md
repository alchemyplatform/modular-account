# SMA7702 Raw EOA ERC-1271 Signatures

## Purpose and scope

Some applications dispatch exclusively on whether a signer has code. An EIP-7702 delegated EOA has code while
retaining its private key, and its wallet may produce a plain EOA signature without knowing that the address is
delegated. Permit2 is a concrete example of an integration that routes this signature through ERC-1271.

For compatibility with these integrations, `SemiModularAccount7702.isValidSignature(bytes32,bytes)` accepts
canonical 65-byte ECDSA and 64-byte ERC-2098 signatures directly over its caller-supplied digest.

Raw recovery must equal `address(this)`, the delegating EOA. This is another encoding for the already-root EOA key,
not a new signer or authority path.

A verifier does not depend on this path for signature formats that it successfully recovers as ECDSA before
trying ERC-1271. In the OpenZeppelin version used by this repository,
`SignatureChecker.isValidSignatureNow` recovers 65-byte signatures first, but its bytes-based recovery does not
accept 64-byte ERC-2098 signatures. The compact form therefore still routes through ERC-1271.

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
revocation.

Execution hooks, hooks on the fallback direct-call key or another validation, and the fallback validation's
`isGlobal`, `isSignatureValidation`, and `isUserOpValidation` flags do not control raw mode. Those flags are inert
for native fallback validation generally: the SMA fallback paths short-circuit the standard flag checks and treat
the fallback as global.

On SMA7702, `updateFallbackSignerData(address(0), false)` restores `address(this)` as the effective fallback
signer; it does not disable anything.

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

The raw ERC-1271 digest is not wrapped with the account's replay-safe domain. Chain, protocol, nonce, deadline, and
action binding therefore come from the digest supplied by the calling application, matching ordinary EOA
semantics for digest binding.

A canonical bare signature created before delegation, or while raw mode was inactive, can validate when raw mode
is active if the calling application supplies the same digest and its own nonce, deadline, and revocation state
still permit the action.

Re-delegating an existing SMA7702 v1.0.0 EOA to v1.1.0 activates raw mode if the three gates above are satisfied. A
still-live bare approval that a codesize-only verifier rejected solely because v1.0.0 lacked this path can then
validate. Before re-delegating, use the application's nonce or revocation controls, including blanket invalidation
where supported, or keep raw mode inactive if that is not intended.

The other SMA variants do not implement bare-signature dispatch.
