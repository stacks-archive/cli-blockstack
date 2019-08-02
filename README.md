## Intended Audience

This tool is meant for **developers only**
-- it is meant to be used for testing and debugging Blockstack apps in ways that
the Browser does not yet support.  It is not safe to use this tool for
day-to-day tasks, since many commands operate on unencrypted private keys.
Everyone is encouraged to use the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser) whenever possible.

## How to Install

You can install the CLI by cloning the repo and running `npm run build`, as
follows:

```
$ npm install -g https://github.com/blockstack/cli-blockstack
```

This should install `blockstack-cli` to your `$PATH`.

`node_modules` directory, for example.

## How to Use

The CLI has a built-in help system.  Just run `blockstack-cli` to access it.
You can list all command documentation with `blockstack-cli help all`.

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
