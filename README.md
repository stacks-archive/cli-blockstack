## This is the legacy version of the Blockstack CLI that supports Stacks blockchain 1.0 transactions only. A new branch with support for Stacks blockchain 2.0 is being worked on here: https://github.com/blockstack/cli-blockstack/pull/40

## Intended Audience

This tool is meant for **developers only**
-- it is meant to be used for testing and debugging Blockstack apps in ways that
the Browser does not yet support.  It is not safe to use this tool for
day-to-day tasks, since many commands operate on unencrypted private keys.
Everyone is encouraged to use the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser) whenever possible.

## Installation

#### Requirements
* [Node.js](https://nodejs.org/en/download/) v8 or higher (v10 recommended).
* [`nvm`](https://github.com/nvm-sh/nvm) is recommended for MacOS & Linux users to avoid `sudo` or [permissions problems](https://docs.npmjs.com/resolving-eacces-permissions-errors-when-installing-packages-globally).

#### Install the CLI

```
$ npm install -g https://github.com/blockstack/cli-blockstack
```

This should install `blockstack-cli` to your `$PATH`.

#### Troubleshooting

If running into `EACCES` permissions errors:
* See https://docs.npmjs.com/resolving-eacces-permissions-errors-when-installing-packages-globally.
* Use [`Node Version Manager`](https://github.com/nvm-sh/nvm).

## How to Use

The CLI has a built-in help system.  Just run `blockstack-cli` to access it.
You can list all command documentation with `blockstack-cli help all`.

### Examples

```
$ blockstack-cli gaia_listfiles --gaia_hub "https://hub.blockstack.org" --app_private_key 3fb610986b2f80af87508ed3b699c4146cb4589264e521402fae6c4f969ab09e
/documents/1564791377194.json
/documents/1564791386260.json
/documents/1564791394787.json
documentscollection.json
key.json
5
```

## How to Contribute

This tool is targeted towards Blockstack developers.  Patches to fix bugs are
welcome!

### Project Scope

The following featuers are considered in-scope for this tool:

* Generating and broadcasting all supported types of Blockstack transactions
* Loading, storing, and listing data in Gaia hubs
* Generating owner, payment and application keys from a seed phrase
* Querying Blockstack Core nodes
* Implementing a minimum viable authentication flow

Everything else is out of scope.  Specifically, the following will **not** be
added to this tool:

* Anything that requires persistent disk state -- this includes software wallets, configuration
  files, and so on
* Anything that involves administrating other Blockstack services
* Features specific to a particular Blockstack app
* Any sort of plugin or extension system

### How to Reach Other Blockstack Devs

The best place to discuss CLI and app development is on the [Blockstack
Forum](https://forum.blockstack.org).
