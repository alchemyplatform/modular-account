# Module Lifecycle Callbacks

## Purpose and scope

This document describes the ordering and failure semantics of module `onInstall` and `onUninstall` callbacks during
`installValidation` and `uninstallValidation`. It applies to every Modular Account variant, and describes behavior
implemented in `src/account/ModuleManagerInternals.sol` and `src/libraries/ModuleInstallCommonsLib.sol`.

Two properties matter to anyone writing a module or composing a validation out of modules written by someone else:
lifecycle callbacks run while account authorization is in an intermediate state, and `onUninstall` is a best-effort
notification rather than a guaranteed one.

## Installation ordering

`_installValidation` proceeds in this order:

1. `_setValidationFunction` stores the validation module address, the validation flags, and every direct-call
   selector supplied in the same call.
2. For each entry of the `hooks` array, in array order: the hook count is incremented, the hook is inserted into its
   linked list, and that hook module's `onInstall` is called.
3. After every hook has been installed, the validation module's own `onInstall` is called.

A hook's `onInstall` therefore observes the validation module, its flags, its selectors, and all *earlier* hooks. It
does not observe later hooks. A restrictive hook positioned later in the array does not constrain an earlier hook's
callback. Direct-call selectors granted by the same `installValidation` are already active when the first hook
callback runs.

The validation module's `onInstall` runs last and observes the complete configuration.

Installation callbacks are not fault-tolerant. `ModuleInstallCommonsLib.onInstall` bubbles a failed callback as
`ModuleInstallCallbackFailed` and the whole transaction reverts, including counter and linked-list updates. A
callback is skipped entirely when its install data is empty.

## Uninstallation ordering

`_uninstallValidation` proceeds in this order:

1. If `hookUninstallData` is non-empty, `onUninstall` is called on each pre-validation hook module, then on each
   execution hook module.
2. The validation hook list, the execution hook list, and the selectors are cleared.
3. `_removeValidationFunction` clears the module address, the validation flags, and both hook counts.
4. The validation module's own `onUninstall` is called.

Every *hook* callback therefore runs while the validation being removed is still fully installed: its selectors,
flags, and hooks are all still live. Only the validation module's own callback runs after the clear, by which point
that authority is gone.

## Implications for integrators

Treat lifecycle callbacks as trusted execution that the final hook policy does not protect.

Installing a module as a hook does not by itself grant it account-management authority. A callback that attempts a
nested account mutation fails without separate authorization. The exposure requires an `installValidation` that
*also* grants the callback module the authority that its final hook set is meant to constrain.

Practical rules:

- Never grant account-management selectors — `installValidation`, `uninstallValidation`, `installExecution`,
  `uninstallExecution`, `execute`, `executeBatch` — to a validation whose hook modules are not trusted.
- Install a validation and its complete hook set in a single `installValidation` call. Do not stage the install
  across transactions and rely on the intermediate state being constrained.
- Review a hook module used alongside an authority-granting validation as though it runs unhooked, because during
  its own lifecycle callbacks it does.

See also [Runtime validation selector authority](../README.md#runtime-validation-selector-authority) for the
related `SemiModularAccount7702` case, where a single granted selector is root-equivalent.

## `onUninstall` is a best-effort notification

A module may never observe its own uninstall, for three independent reasons:

1. **Short circuit.** Callback results are aggregated with `&&`. Once any callback has failed, Solidity
   short-circuits the remaining operands, so no later hook callback and no validation-module callback is *called at
   all*.
2. **Empty data.** `ModuleInstallCommonsLib.onUninstall` calls the module only when its uninstall data is non-empty,
   and the hook loop runs only when `hookUninstallData` is non-empty. An empty array skips every hook callback.
3. **Swallowed reverts.** A reverting `onUninstall` is caught rather than bubbled. It records failure and removal
   continues.

In all three cases the account-side removal completes: hooks, selectors, flags, counts, and the validation function
are cleared regardless. The aggregate result is reported as the third parameter of
`ValidationUninstalled(address indexed module, uint32 indexed entityId, bool onUninstallSucceeded)`.

Module authors must not use `onUninstall` for security-critical cleanup. Module state must be safe when left stale.
Key state by account and entity id, and re-initialize it in `onInstall` rather than assuming a prior `onUninstall`
cleared it.

Clients should read `onUninstallSucceeded` from the event rather than assuming cleanup ran. When a specific module
must be notified, uninstall it in its own transaction so that another module's failure cannot mask it.

## Hook uninstall data ordering

`hookUninstallData` is ordered pre-validation hooks first, then execution hooks. Within each group the order is the
**reverse** of the corresponding array returned by `getValidationData`.

`ModularAccountView.getValidationData` reverses both hook arrays before returning them, while `_uninstallValidation`
iterates the underlying linked lists directly without reversing. The public view order and the uninstall order are
therefore opposite.

When the array is supplied, its length must equal `validationHooks.length + executionHooks.length` or the call
reverts with `ArrayLengthMismatch`. Length is checked; order is not. Supplying the display order without reversing
sends each module another module's uninstall data, which usually produces silent failure rather than a revert,
because reverts in this path are swallowed.

Pass an empty array to skip hook callbacks entirely.
