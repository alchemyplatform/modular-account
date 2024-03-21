## Session Key Plugin

### Core Functionalities

Session Key Plugin is a plugin where session keys can be added to conduct various actions on behalf of the modular account under preset rules. **Session keys are used in user operation context only.**

Its core features include:

- Supports an expiry and time range rules that restrict session keys’ access to a specified time range.
- Supports external contract address limitations that limit what external contract addresses a session key is allowed to call. This restriction may be an allowlist, denylist, or neither.
- Supports external contract method limitations, which limit what external contract functions a session key is allowed to call.
- Support key rotation to update the key while keeping the permissions in place.
- Default permissions restrict everything, all access must be explicitly granted.
- Supports ERC-20 spend limits. These may be a total for the key, or refreshing on an interval (e.g. once per week).
- Supports ETH / native token spend limitations. These may be a total for the key, or refreshing on an interval.
- Supports gas spend limitations (total for a key, or refreshing on an interval).
- Supports ERC-721 permission through selector access limitations.
- Supports a required paymaster rule, where a session key may only be used to validate a user operation if a specific paymaster address is used. This is an alternative way to prevent session keys from spending your native token on gas than the gas limit.

### Technical Decisions

**Session keys are only used during User Operations context**

Session keys are intended to ephemeral signers, that may expire, rotate, or be refreshed by the owner. As such, it does not make sense to use their EOA address to hold assets or be used as the sender in a transaction. The use of secp256k1 as the signature mechanism is just for efficiency and simplicity within the EVM, and the address associated with these private keys is not intended to be used

**Session keys may not be contracts**

In a similar vein as above, the session keys and their permission management system are not designed to be used with contract owners or signers. These keys are designed to be ephemeral, and smart contracts are not ephemeral.

**Native token spend limits and gas spend limits are tracked separately**

Although the prevailing use case might be to limit _any_ outflow of the native token from the account (i.e., transfers + gas fees), gas spend limits are tracked separately in this session key implementation to allow for scenarios where the user may want to limit transaction fee expenses separately from actual spend for goods and services.

**No “refunds” are given when a session key reduces an allowance**

To simplify the accounting system, once a session key spends some of its ERC-20 spending limit via `approve`, it cannot later revoke that approval and spend that portion of the budget elsewhere.

**Session Key Signature Spec**

The session key signatures themselves are actually in the same format as a regular ECDSA user op signature, which is a signature over the user op hash. Similar to the existing pattern of user op signing, it uses personal_sign to wrap the data to be signed per EIP-191: https://eips.ethereum.org/EIPS/eip-191

The session key address is added to calldata, through a custom method called executeWithSessionKey that take in the batch of calls to make and the session key address.

And just like non-session-key user ops that use the owner's signature, you can use a dummy ECDSA signature for gas estimation. In short - the signature format is actually really simple, because it leverages stateful permissions instead of the very big merkle proofs for signatures like Kernel constructs.

**Session Keys clear permissions when removed**

Session keys are removed when the owner calls `removeSessionKey` or if the session key plugin is uninstalled. These two actions both clear the permission state of the session key, meaning if that same session key is added again, all of its permissions will start at the default values. This prevents unintentional permissions from being inherited due to previous state.

A similar situation happens when using `rotateSessionKey` to replace a key. This function will remove the old session key, add a new session key, and transfer permissions from the old key to the new key. If the address of the old session key (which was rotated away) is added back via `addSessionKey`, its permissions will start at the default values, rather than copying their old values.

### Restrictions and Caveats

**ERC-20 Spend Limits only track calls to `transfer` or `approve`.**

Session key ERC-20 spending limits only check and enforce the limits over calls to `transfer` or `approve`. When calling `approve`, the amount approved counts towards any limits that have been set, even if the approval is below the existing allowance.

This limitation is kept because decoding calldata follows a known pattern established by the ERC-20 specification itself. Attempting to decode calldata towards other unknown contracts that then use `transferFrom` is not possible to generalize. Alternatively, one may consider a storage checks via `balanceOf` as an enforcement mechanism for ERC-20 spending limits. However, this can be spoofed. For instance, a batch action that spends 1000 USDC but also withdraws 900 USDC from Compound would appear to only spend 100 USDC, and it is impossible to protect from this category of spoofs without knowledge of every application a user may interact with.

In addition, by only tracking `transfer` and `approve` calls, ERC-20 tokens with non-standard methods to transfer tokens or change allowances will also not be captured by the spending limits. These functions may be restricted via the access control system.

**ERC-20 Spend Limits are only enforced during execution.**

As described above, ERC-20 spend limits decode calldata to detect if an ERC-20 spend is occurring. All limits enforcement happens during the execution phase, within a pre execution hook.

If a permission is violated, the call will revert, but some gas will be spent. Any session key using ERC-20 spend limits should set either a gas spending limit, or a required paymaster, to prevent a gas griefing attack on the account.

**Gas Spend Limit Restriction**

If you're using a session key with a gas limit, the "key" portion of the nonce must be equal to the session key address. This is to protect an account’s reputation with bundlers if it is staked, and capable of submitting multiple user operations to include in the same bundle. Enforcing gas spending limits has a side effect of updating storage during validation. If multiple session key user operations are included in a single bundle, a later one’s validation phase may fail based on the effects of the storage write of the first usage. To protect from this, we require a sequential nonce track per session key used. This ensures bundlers either don’t accept them in the same bundle, or if they have the capability of simulating across multiple sequential user operations, they will accurately be able to determine if validation will succeed or fail.

**Gas spend limits will consistently overestimate the gas usage of a session key**

Gas spending limits calculate the gas spend of a user operation by its maximum possible gas usage, rather than its actual gas usage. This is done because the lack of hook ordering control makes it impossible to accurately measure how much will be used during validation or execution. In practice, most user operations will use somewhat less gas than their gas limits, so the gas spending limits should be set with this in mind. They may also be updated later.

Offchain, you can measure the total usage by finding the user ops that used the session key by checking the calldata’s session key address parameter, then summing up the actual gas used in the `UserOperationEvent` fields.

**Gas spending limits may freeze a session key if refresh intervals are enabled and too many calls revert, but anyone can unfreeze it.**

Spending limits for native tokens, ERC-20 tokens, and gas spending supports refreshing along an interval. This can be described as “My usage of the limit resets to zero if a time interval has passed”. While it behaves as expected for native tokens and ERC-20 tokens, there are a limited number of edge cases in the gas spending limit that session key implementers need to consider.

Normally, when the boundary for a refresh interval is crossed, during execution the “last used timestamp” field is updated to the current `block.timestamp`. However, execution may revert, and unlike with native token and ERC-20 spending, a revert does not undo the spending of gas. Thus, if a revert happens during execution when the gas limit is crossed from one interval to the next, the last used time will not be updated.

The permission state that the “last used timestamp” should be updated is tracked with a boolean flag value. If an interval boundary is crossed, it is set during validation. If execution reverts, this flag will remain set after the user operation completes. If there is still enough remaining gas spend in the next interval to perform additional calls, this inconsistent state can be fixed just by performing a user operation whose execution phase does not revert using the session key. Normally this will give you enough “retries” to get the flag unstuck, provided the limits are set at reasonable values.

However, in the event that the next interval’s spend limits are fully used up exclusively with reverting executions, the session key will be stuck until either the owner manually resets the “last used timestamp” to `block.timestamp` using the permissions configuration method, or if anyone calls the `resetSessionKeyGasLimitTimestamp` function on the plugin.

**Gas spend limits with a refresh interval will not refresh the last used time until the previous one is exceeded.**

Continuing with more details about the refresh intervals on gas spending limits, native token spending limits and ERC-20 spending limits will have their last used timestamp skipped forward to `block.timestamp` if they are used at all after the previous interval expires, regardless of how much they use. This is not the case for gas spending limits, however, for these limits the last used timestamp is only advanced if the previous interval is completely used. This happens because the execution phase does not have knowledge about what happened during validation without expensive storage writes, which we’ve chosen to limit only to the “should update last used” flag.
