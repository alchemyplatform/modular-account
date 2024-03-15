## Multi Owner Plugin

### Core Functionalities

Multi Owner Plugin is an ERC-6900 compliant plugin where one or more EOA accounts or ERC-1271 compliant contracts can be owners of the MSCA. Its core features including:

- Enable ECDSA verification of signatures, standard EOA signatures verification.
- Enable ERC-1271 signature verification, standard contract owner signatures verification.
- Multiple equal owners who have the same root access to account.
- Implements EIP-712.
- By default, owner validation is added for most of MSCA’s native functions including:
  - `installPlugin`/ `uninstallPlugin`
  - `upgradeToAndCall`
  - `execute` / `executeBatch`

### Technical Decisions

**MSCA multi owner plugin upgrade path**

The deployed modular account comes with an ownership plugin determined by the factory. Since there is no default owner or other validation methods for the MVP modular account, MSCA users wanting to swap out the ownership plugin must upgrade it through a special pathway:

- Batch uninstalling current owner plugin and installing new owner plugin into one UO tx through `executeBatch`.

### Restrictions and Caveats

**Owners of MSCA cannot directly be `sender` of children MSCAs due to ERC4337 storage access rules**

Multi Owner Plugin stores owners of MSCA at the associated (MSCA address) storage location.

For an `MSCAa` who has an owner that is also an `MSCAb`, `MSCAa` won’t be able to have `MSCAb` to verify if a signature is valid or not due to the ERC-4337 restriction that `MSCAb` won’t be able to access its associated storage slots. This renders `MSCAb` unable to verify signatures from `MSCAa`. Instead, as the owner of `MSCAb`, `MSCAa` can directly call execution functions on `MSCAb` where owners are allowed to call (for example, native functions like `execute` or `executeBatch`) to execute a transaction through the child account `MSCAb`(with `sender` = `MSCAa`) and make modifications to `MSCAb`.

**Invalid owners can brick an account and may cause fund loss**

When updating owners, if the user supply invalid addresses (aka addresses that user does not have access to) as owners, the MSCA can be rendered as unusable. This can happen while setting up the MultiOwnerPlugin, or while user update the owner list later.

Even though we have checks in place for common mistakes, there is no easy way to prevent users adding wrong addresses that they don’t have access to without sacrificing user experience.

This is an user error that is very tricky to prevent from the contract side. Client should educate users to avoid making such a mistake.

Also see [**Invalid owners will cause fund loss**](https://www.notion.so/Invalid-owners-will-cause-fund-loss-89f30e5019db4ee89b295d837acb0a52?pvs=21)

**A malicious owner may front run a benign owner**

Due to the nature of equal weighting of all owners, in the case where one owner's account is compromised or turns malicious, another benign user would attempt to remove the malicious one from the owner list via updateOwners(). Theoretically, that would work, but due to the blockchain nature, the malicious entity can monitor the memory pool and front-run the updateOwners() with updateOwners() of their own, removing the benign owner, hence causing their removal to revert due to lack of permissions.
