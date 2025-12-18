# Architecture

## Goals

Modular Account aims to support the ability to:

- represent different key types using validation functions
  - limit the scope of what each validation function may authorize, to enforce defense-in-depth
- use hooks to apply permissions over keys
  - apply these permissions subtractively, to only pay gas for what you use
- conform to arbitrary external function interfaces for smart contract composability
- defer initialization steps until the account is actually used, including steps like provisioning keys and approving tokens
- send transactions outside of the ERC-4337 user op context
  - Support nested smart account ownership logic, where calls cannot re-enter the entrypoint

## Architecture Overview

The Modular Account contract suite consists of:

- Account factories:
  - These allow for deterministic crosschain deployments of accounts as [ERC-1967](https://eips.ethereum.org/EIPS/eip-1967) proxies
  - `AccountFactory`: supports deploying each account type SemiModular, SingleSigner, WebAuthn
- Account implementation contracts:
  - These manage module installation state and scope.
  - `SemiModularAccountBytecode` (SMA-B): The most efficient account to deploy, holds the initial owner in proxy bytecode. Only compatible with using `AccountFactory` for deployment, cannot upgrade from other proxies to this.
  - `SemiModularAccountStorageOnly` (SMA-S): Similar to SMA-B, but works for upgrading other account types into this account.
  - `ModularAccount`: Account that only manages module state, all ownership logic exists in modules.
- Module Contracts
  - Validation Modules
    - `SingleSignerValidationModule`: supports secp256k1 ECDSA owners or ERC-1271 contract owners.
    - `WebAuthnValidationModule`: supports WebAuthn (passkey) owners by validating secp256r1 signatures.
  - Permission modules
    - `AllowlistModule`: Enforces ERC-20 spend limits and address/selector allowlists.
    - `NativeTokenLimitModule`: Enforces native token spend limits.
    - `PaymasterGuardModule`: Enforces use of a specific paymaster.
    - `TimeRangeModule`: Enforces time ranges for a given entity.

## Concepts

## Entity IDs

Because the module contracts hold state, each module must distinguish between accounts, and between multiple installations on the same account. This is necessary because an account can have multiple owners of the same key type - for example, two ECDSA keys can be owners on the same account.

An entity ID uniquely identifies the "instance" of state per module in a `uint32`. The combination of module address and an entity ID is referred to as a "module function".

For Modular Account specifically, entity IDs for validation functions must be globally unique. This is not a requirement of the ERC-6900 standard, but is used here to allow for more compact packing of validation selection. See [Data-Encoding.md](./Data-Encoding.md) for more details.

## Validation functions

Validation functions represent a mechanism for validation actions for the account. These actions can be sending user operations, signing ERC-1271 messages, or authorizing calls during the execution phase.

It is possible to layer permission restrictions on validation functions using hooks. It is also possible to limit the blast radius of a validation function by setting limited account scopes per function, or they can be included in a shared pool of functions called "global validation".

Users must select which validation function is used each time it is required, for gas efficiency.

## Hooks

Hooks are module functions that run in addition to another account function, and multiple hooks can be installed for the same account function. There are two types of hooks: validation hooks and execution hooks.

### Validation hooks

Validation hooks are attached to validation functions when they are installed. They run in the order of installation, and before the validation function.

Validation hooks can accept unique data per-validation hook each time they run. This can be used to implement checks that require custom data to verify, such as proof of inclusion in a merkle tree. See [Data-Encoding.md](./Data-Encoding.md) for details on how to specify data to each validation hook.

Validation hooks apply to all of user op validation, runtime validation, and signature validation. If you want to disable a specific option through a hook, the module should always revert. If you want to avoid checks on a specific validation type, always pass.

Specifically for user op validation, the resulting time range is coalesced between all validation hooks and the validation function. Coalescing takes the intersection of the time range for validity.

### Execution hooks

Execution hooks run in the execution phase of ERC-4337. They can either be attached to a validation function, or attached to an execution function.

Validation-attached execution hooks will run whenever that validation function is used, regardless of account function being invoked. They also require use of the EntryPoint v0.70+ function `executeUserOperation` to encode user operation details in execution phase.

Execution function attached hooks will only run when that specific execution function is run, regardless of validation function.

## Execution functions

Execution functions allow the account to implement arbitrary external functions. Installing them also allows the account to report that it supports a specific interface via ERC-165.

View functions, or functions that don't require validation, are supported by specifying the `skipRuntimeValidation` flag.

## Module State Management

Modules are responsible for storing their own state per-account, with state initialized using the `onInstall` function.

The account state generally only manages which modules are installed, what type they are, and what account functions they apply for.

### Module Installation and Uninstallation

There are four functions for managing module installation state on the account: `installValidation`, `uninstallValidation`, `installExecution`, and `uninstallExecution`.

#### `installValidation`

**Parameters:**

- Packed into `ValidationConfig`:
  - Module address
  - Entity ID
  - Validation options:
    - `isGlobal`: has permission to validate any global account function.
    - `isSignatureValidation`: has permission to validate ERC-1271 signatures.
    - `isUserOpValidation`: has permission to validate user operation signatures.
    - (Ability to validate runtime calls is implicit and cannot be disabled.)
- List of selectors to be allowed to validate, outside of the global pool.
- Installation initialization data. If provided, the account will call out to the newly installed validation module's `onInstall` function with the provided data.
- Hooks. Provided as a list of `bytes`, with a packed encoding containing:
  - HookConfig: packed data containing
    - Hook Module address
    - hook entity ID
    - hook options:
      - Enum option for either Validation Hook or Execution hook
      - (If an execution hook) individual flags for being a pre execution hook, post execution hook, or both.
  - Hook `onInstall` data
    - If provided, the account will call out to the hook module's `onInstall` function with this data after installation.
  - Hooks will be installed in the order they are provided, added to the installation state for each hook type.

#### `uninstallValidation`

**Parameters:**

- Packed into `ModuleEntity`:
  - Validation module address
    - (due to account-specific optimization, this is actually not checked, because validation entity ID uniquely identifies validation function)
  - Validation Entity ID
- Uninstall data
  - If provided, account will make call to module's `onUninstall` function using this data.
- Hook uninstall data list
  - Optional - can either be provided, or not.
  - If not provided, hooks are uninstalled without ever calling `onUninstall` - only account state is updated. This will usually retain state on the hook modules for this account address and the previously used entity ID.
  - If provided:
    - the list must be exactly as long as the number of validation hooks + the number of execution hooks.
    - The list will be interpreted as the hook uninstall data for the validation hooks first, in order, then the execution hooks, in order.
    - If any piece of data is empty, the call to `onUninstall` is skipped for that hook.

#### `installExecution`

**Parameters:**

- Module address
- List of functions to install. Each function contains
  - Function Selector
  - Flags:
    - Skip runtime validation: to disable validation functions from running if called directly on the account. Useful for view functions or permissionless functions.
    - Allow global validation: whether this function on the account should be considered part of the global validation pool.
- Execution hooks
  - Function selector to attach to.
  - Hook entity ID.
  - Flags to indicate pre execution hook, post execution hook, or both.
- List of interface IDs to report as supported by the account.
- Module install data: If provided, the account will call `onInstall` on the execution module with the provided data.

#### `uninstallExecution`

**Parameters:**

- Module address
- List of function selectors to remove
- List of execution hooks to remove
- List of supported interfaces to remove
- Module uninstall data: If provided, the account will call `onUninstall` on the execution module with the provided data.

## Batching and privilege escalation prevention

Modular Account supports batching multiple actions into a single transaction. This can be done using the `executeBatch` function.

For calls to external contracts, batching is very straightforward: simply encode all external calls into the `Call[]`, and they will execute in order, and atomically - if a single call reverts, the entire batch will revert.

It is also possible to batch multiple calls on the account itself using `executeBatch`. To do this, you should set the `target` of each function call on the account to the account's own address. Note that in this case, the validation applicability checks will still apply over the functions being called, to prevent privilege escalation. To simplify the mechanism for verifying validation applicability, Modular Account requires that all self-calls must be flattened into a single call to `executeBatch` - meaning that the self-calls within the batch cannot themselves be calls to either `execute` or `executeBatch`.

If you are executing a single call on the account, you should not use the `execute` function pointing to the account itself - instead, the calldata you are trying to run should be unrolled and used as the calldata in the user operation or runtime call.

## Semi-Modular Account Support

Account deployment can make up a significant portion of the cost of the first user operation, so minimizing deployment gas costs is a key optimization goal. The Semi-Modular Account (SMA) variants address this by implementing a "semi-modular" architecture: they retain full support for installing modules while also providing a built-in fallback validation function directly in the account contract itself.

This built-in fallback validation logic is associated with the reserved validation entity ID `0`. The fallback signer address can be loaded either from the proxy bytecode or from storage, depending on the SMA variant used. The fallback validation supports the same signature validation as `SingleSignerValidationModule`, including both EOA (secp256k1 ECDSA) and contract owner (ERC-1271) signatures.

### Variants

There are three Semi-Modular Account implementation variants, each optimized for different deployment scenarios:

**SemiModularAccountBytecode (SMA-B)**: This is the most gas-efficient account implementation for new deployments. The initial owner address is appended to the proxy bytecode using Solady's `LibClone` ERC-1967 with immutable args pattern. The account reads the fallback signer from the proxy bytecode if the storage slot is zero and fallback validation is not disabled. This variant can only be deployed through `AccountFactory` and cannot be used as an upgrade target from other account implementations due to its reliance on specific proxy bytecode.

**SemiModularAccountStorageOnly (SMA-S)**: This variant stores the fallback signer address entirely in storage, making it compatible with upgrading from other account types. It includes an `initialize()` function to set the initial fallback signer, which should be called via `upgradeToAndCall()`. While slightly less gas-efficient than SMA-B for new deployments, SMA-S provides upgrade compatibility that SMA-B cannot support.

**SemiModularAccount7702**: This variant is designed specifically for use with EIP-7702, which allows EOAs to delegate execution to a smart contract implementation. When used as an EIP-7702 delegate, the fallback signer defaults to `address(this)` (the EOA's own address). This allows EOAs to gain smart account functionality while retaining their original address as the default signer. The `upgradeToAndCall()` function is disabled for this variant since EIP-7702 accounts delegated to this contract would not be able to upgrade using this function.

## Deferred Actions

Deferred actions allow initialization or setup calls to run during the user operation validation phase, before the main validation logic executes. This capability addresses specific initialization patterns that would otherwise require separate transactions or introduce circular dependencies.

### Motivation

There are scenarios where an account needs to perform setup operations atomically with a user operation, but before validation can proceed. Two common examples illustrate this need:

**Session Key Installation**: When a user wants to install a session key with specific permissions and immediately use it to authorize a transaction, installing the key in a prior transaction from the owner creates friction. It adds transaction confirmation latency at sign-in time, and wastes gas if the session key is provisioned but never actually used.

**ERC-20 Token Paymaster Approvals**: If an account wants to use an ERC-20 token paymaster that pulls tokens from the account during the ERC-4337 validation phase, there is a circular dependency problem. The account needs to approve the paymaster before the paymaster can sponsor gas, but the first transaction to call `approve` cannot be sponsored if the account doesn't already have approval set up.

While these scenarios could theoretically be handled with separate transactions or user operations, that approach introduces latency, wastes gas on unused installations, or creates dependency loops that prevent certain patterns from working at all.

### Solution

Deferred actions solve this by allowing an account to authorize an action to execute during user operation validation, before the primary validation function runs. The mechanism works by having the user sign an EIP-712 typed data structure containing the details of the deferred action. During user operation validation, this signed struct is included in the user operation signature, and the account verifies the signature and executes the action before proceeding with the rest of validation.

The validation function used to authorize the deferred action can be different from the validation function used to validate the user operation itself. This flexibility is essential for patterns like deferred session key installation, where the owner's validation authorizes installing a new session key, and then that newly-installed session key is immediately used to validate the actual user operation.

See [Data-Encoding.md](./Data-Encoding.md#signature-structure-with-deferred-actions) for detailed information on how to encode deferred actions in user operation signatures.

### EIP-712 Struct Definition

The deferred action is defined as an EIP-712 typed data structure:

```
DeferredAction(uint256 nonce, uint48 deadline, bytes call)
```

**Nonce**: The user operation nonce that this deferred action is valid for. The account does not independently manage nonces for deferred actions, and instead reuses user operation nonces to bind the deferred action to a specific user operation. To invalidate an unused deferred action signature, the account should call [`incrementNonce`](https://github.com/eth-infinitism/account-abstraction/blob/v0.7.0/contracts/interfaces/INonceManager.sol#L26) on the EntryPoint contract using the nonce key the deferred action was signed for. Per the [user operation nonce encoding specification](./Data-Encoding.md#user-operation-nonce), the nonce used here must have the "has deferred action" bit set in the options byte.

**Deadline**: A block timestamp (as `block.timestamp`) past which the deferred action is no longer valid. Setting this to `0` means the deferred action has no expiration. The deadline provides time-bound validity for deferred actions and allows them to expire if not used within a certain timeframe.

**Call**: The calldata for an account self-call to perform before user op validation. This is typically a call to `installValidation` to install a new validation function, but could be any account function. If you wish to interact with an external contract as part of the deferred action, wrap the external call in `execute` or `executeBatch`. Validation scope applicability rules still apply to deferred action calls, so the call must be to an account function that the validation function authorizing the deferred action is allowed to invoke.

### Validation Time Bounds

When a deferred action is executed, the validation time bounds returned by the deferred action's validation and the primary user operation validation are coalesced using time range intersection. This ensures that the resulting time bounds for the user operation are the most restrictive of the two validations.

### Restrictions and Caveats

**Signature Validation Requirement**: Only validations that have the `isSignatureValidation` flag enabled may authorize deferred actions. This is because deferred actions are validated using the ERC-1271 signature validation path, which requires this flag to be set during validation installation.

**No Validation Hooks**: If a validation function has any validation hooks attached, it may not authorize deferred actions. This is a technical restriction that exists because the deferred action authorization flow does not fit the shape of a standard user operation, runtime, or signature validation call, and thus cannot properly invoke validation hooks.

**User Operation Hash Independence**: Because the entire deferred action is encoded within the user operation signature field, it does not affect the user operation hash beyond the `hasDeferredAction` flag in the nonce. This means that a malicious man-in-the-middle (such as a bundler) could potentially swap deferred action contents if it knows of multiple valid, signed deferred actions for the same nonce. This can be mitigated by:

- Only providing deferred actions that are necessary for the user operation to validate. Both examples described above (installing a session key and approving an ERC-20 token paymaster) satisfy this criteria, as the user operation would fail validation without the deferred action executing successfully.
- Only publicly broadcasting one unmined deferred action at a time to avoid giving potential attackers access to multiple valid alternatives.

## Direct Call Validation

Direct call validation allows modules and other contracts to call functions on the account without wrapping the call in `executeWithRuntimeValidation`. This provides a simpler execution path when no additional authorization data is needed beyond verifying the caller's identity (`msg.sender`).

### Mechanism

Validation functions installed with the reserved entity ID `0xFFFFFFFF` (`type(uint32).max`) are treated as direct call validations. When the account receives a function call from an address that is neither the account itself nor the EntryPoint, it attempts to use direct call validation. The account checks whether the caller's address has a direct call validation function (entity ID `0xFFFFFFFF`) installed that applies to the function being called. If such a validation exists, the account allows the call to proceed without requiring a call to `executeWithRuntimeValidation`. Any validation hooks and execution hooks associated with this direct call validation still run as normal.

### Rationale

Direct call validation serves two primary purposes. First, it provides compatibility with legacy contract systems that expect to call functions directly on accounts without understanding modular account-specific interfaces like `executeWithRuntimeValidation`. Second, it reduces gas costs by eliminating the overhead of the runtime validation dispatcher when the only validation needed is to check `msg.sender`. This makes direct call validation the most gas-efficient option for simple caller-based authorization patterns.

## Runtime Validation for Nested Account Ownership

The ERC-4337 EntryPoint contract's functions for running user operations (`handleOps` and `handleAggregatedOps`) do not support re-entering the contract. This means that a smart account cannot use its execution phase to process another smart account's user operation, even if it is signed and valid, because the EntryPoint would block execution.

Runtime validation, including direct call validation, enables nested smart account ownership patterns. When one smart account owns another, the parent account can directly call functions on the child account using runtime validation instead of going through the EntryPoint. This allows for flexible account hierarchies and composable ownership structures without the limitations imposed by the EntryPoint's non-reentrant design.
