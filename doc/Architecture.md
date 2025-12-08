# Architecture

## Goals

- represent multiple key types using validation functions
    - Limit scope of validation functions - defense in depth.
- Use hooks to layer permissions over keys, subtractively
    - Philosophy of "only pay gas for what you use"
- Allow the Smart Account to conform to arbitrary external interfaces
- Allow composition of validation functions
- Allow deferred initialization steps
   - For keys
   - For setup (approving ERC-20 paymaster)
- Allow using the account outside of user op context
   - For nested ownership logic - can't re-enter the entrypoint
   - Outside of ERC-4337 context

## Architecture Overview

- Account contract: manages module installation state and scope. Deployed via ERC-1967 proxy.
- Module contracts hold implementation logic and state.
- Module contracts can be any combination of module types - validation, hook, or execution.

- Entity ID:
    - Concept: because the module contracts hold state, must distinguish between accounts, and between multiple installations on the same account. E.g. an account can have multiple owners of the same key type, like ECDSA secp256k1 keys.
    - Entity ID uniquely identifies the "instance" of state per module in an `uint32`.
    - Combination of module address + entity id is a "module function".
    - (For this account specifically): Validation entity IDs must be globally unique. Not a requirement of the ERC-6900 standard, but used here to allow for more compact packing of validation selection. See [Data-Encoding.md](./Data-Encoding.md).


Validation functions

- Functions representing validation of actions for the account.
- Can layer restrictions using hooks as permissions.
- Can limit blast radius by setting limited account scopes (per-function), or into a shared pool of function via global validation.
- User must select which validation function is used each time it is required, for efficiency.

- User op validation: result time range is coalesced

Hooks

- Validation hooks
   - Attached to validation functions
   - Run in order
   - Can accept unique data per-validation hook
   - Apply to all of "user op validation", "runtime validation", and "signature validation". If you want to disable a specific option by hook, the module should always revert. If you want to avoid checks on a specific validation type, always pass.

- Execution hooks
   - Two kinds: attached to validation, attached to execution function
      - validation-attached:
         - Require use of EP v0.7+ `executeUserOperation` to encode user operation details in execution phase.
         - WIll run whenever that validation function is used, regardless of account function.
      - execution function attached
         - will only run when that specific execution function is run, regardless of validation function.



Execution functions

- Allow the account to implement arbitrary external functions
- ALlow the account to report that is supports interfaces via ERC-165
- support view functions via `skipRuntimeValidation` flag


## Module State Management

Concept: state is stored on modules themselves. account state manages only which modules are installed, what type they are, and what account functions they apply for. State must be initialized with `onInstall` function.


- Installation and uninstallation
    - InstallValidation
        - Parameters
            - Packed into `ValidationConfig`
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

    - UninstallValidation
        - Parameters
            - Packed into `ModuleEntity`:
                - Validation module address
                    - (due to account-specific optimization, this is actually not checked, because validation entity ID uniquely identifies validation function)
                - Validation Entity ID
            - Uninstall data
                - If provided, account will make call to module's `onUninstall` function using this data.
            - Hook uninstalldata list
                - Optional - can either be provided, or not.
                - If not provided, hooks are uninstalled without ever calling `onUninstall` - only account state is updated. This will usually retain state on the hook modules for this account address and the previously used entity ID.
                - If provided:
                    - the list must be exactly as long as the number of validation hooks + the number of execution hooks.
                    - The list will be interpretted as the hook uninstall data for the validation hooks first, in order, then the execution hooks, in order.
                    - If any piece of data is empty, the call to `onUninstall` is skipped for that hook.
    
    - InstallExecution
        - Parameters:
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
    - UninstallExecution
        - Parameters:
            - Module address
            - List of function selectors to remove
            - List of execution hooks to remove
            - List of supported interfaces to remove
            - Module uninstall data: If provided, the account will call `onUninstall` on the execution module with the provided data.

## Batching and privilege escalation prevention
            

## SMA behavior

- Account deployment can make up a significant portion of the cost of the first user operation, so we want to minimize the gas costs of deployment.
- Solution: make the account "semi-modular": still supports modules, but there is also a builtin validation function to the account contract itself.
- This builtin logic only applies to validation entity id 0. Owner is loaded either from the proxy bytecode or from storage. Details in the section in optimizations (TODO: link)

- Storage only vs bytecode variant differences.
- 7702 variant

## Deferred Actions

- Context: sometimes, initialization / setup calls need to run before user op validation. Two samples cases:
    - Setting up a session key's permissions before the key is used.
    - Calling ERC-20 approve for a token paymaster contract that pulls tokens from the account during the ERC-4337 validation phase.
- These could in theory be handled in separate transactions or user operations, but that introduces some issues:
    - For session keys, it is not preferrable to install them in a transaction from the owner prior to use because:
        - This adds an extra transaction confirmation time at sign-in, which introduces latency.
        - If the session key is authorized and provisioned, but never used, then gas is wasted on an installation.
    - For ERC-20 approvals, there is a dependency loop if the account wants to use the ERC-20 token paymaster for all gas - the first transaction from the account would not be sponsorable
- Solution: Allow authorizing an action to run before user op validation, by signing an EIP-712 struct containing the details of the action. During user op validation, this struct and a signature over it can be included in the user operation signature, and the account will verify and run it prior to the rest of user op validation. 
    - See [Data-Encoding.md](./Data-Encoding.md) for more details on how to encode this.

- The validation function used to authorize the deferred action can be different than the validation function used to validate the user operation. This is necessary for deferred installation of session keys.

- EIP-712 Struct Definition:
    `DeferredAction(uint256 nonce,uint48 deadline,bytes call)`
    - Nonce: user operation nonce this deferred action is valid for. The account does not independenlty manage nonces for deferred actions, and instead reuses user operation nonces.
        - To invalidate an unused deferred action signature, the account should call [`incrementNonce`](https://github.com/eth-infinitism/account-abstraction/blob/v0.7.0/contracts/interfaces/INonceManager.sol#L26) on the EntryPoint contract using the nonce the deferred action was signed for.
        - Per the User Op Nonce encoding specification (TODO: link with anchor), the nonce here must have the bit for "has deferred action" set.
    - Deadline: a block timestamp past which the deferred action is no longer valid.
    - Call: the account self-call to perform before user op validation. If you wish to interact with an external contract, this may be `execute` or `executeBatch`.
        - Validation scope applicability rules still apply, so this should be an account function that the chosen validation function is allowed to call.

- Caveats:
    - Only validations that have the `isSignatureValidation` option enabled may grant approvals for deferred actions.
    - If a validation function has any validation hooks attached, it may not grant approvals for deferred actions. This is a technical restriction, because the deferred action intent does not fit the shape of a user operation, runtime, or signature validation function.
    - Because the entire deferred action is encoded in the user operation signature, it does not affect the user operation hash beyond the `hasDeferredActionFlag`. This means that a malicious man-in-the-middle (MITM), such as a bundler, could swap deferred action contents, if it knows of two signed and valid deferred actions at the same time.
        - This can be mitigated by only providing deferred actions that are necessary to execute for the user operation to validate. Both of the examples provided - installing a session key and approving an ERC-20 token paymaster - fit this criteria.
        - Other simple mitigations include only ever publicly broadcasting one unmined deferred action at a time.

## Direct call validation

## Usage of runtime validation for nested account ownership
