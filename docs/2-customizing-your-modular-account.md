# Customizing your Modular Account

The Modular Account v2 can be customized by:
1. Installing executions to add custom execution logic to run, or uninstalling to remove them
2. Installing validations to apply custom validation logic for one or all executions, or uninstalling to remove them
3. Adding pre validation hooks that are attached to validations, or removing them
4. Adding execution hooks that are attached to executions, or removing them
5. Adding execution hooks that are attached to entities, or removing them

### Pre-validation Hooks

Pre validation hooks are run before validations. Pre-validation hooks are necessary to perform gas related checks for User Operations (session key gas limits, or gas metering taking into account paymaster usage). These checks must happen in the validation phase since a validation success would allow the entrypoint to charge gas for the user operation to the account.

### Validations

Validations are usually signature validation functions (BLS, WebAuthn, etc). While it’s feasible to implement signature validation as a pre-validation hook, it’s more efficient and ergonomic to do these in validations since it allows us to apply permissions per entity using execution hooks. In ERC4337, accounts can return validation data that’s not 0 or 1 to signal the usage of a signature aggregator. As such, the account must only have a single 

### Execution Hooks

Execution hooks are useful for applying permissions on executions to limit the set of possible actions that can be taken. Post-execution hooks are useful for checking the final state after an execution. Pre and post-execution hook pairs are useful for measuring differences in state due to an execution. For example, you would use a pre and post execution hook pair to enforce that swap outputs from a DCA swap performed by a session key fall within a some tolerance price determined by a price oracle.

Execution hooks can be associated either with an (validation module + entity ID) pair to apply permissions on that specific entity, or with an execution selector on the account to apply global restrictions on the account across all entities. A example of a useful global restriction would be to block NFT transfers for NFTs in cold storage, or to apply resource locks.

### Executions

Execution hooks are applied across executions. Modular account comes with native executions such as `installValidation`, `installExecution`, or `upgradeToAndCall`. However, you could customize the account by installing additional executions. After a new execution is installed, when the account is called with that function selector, the account would forward the call to the module associated with that installed execution. An example for executions would be to implement callbacks to be able to take flash loans.