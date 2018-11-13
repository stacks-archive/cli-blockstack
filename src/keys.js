/* @flow */

// TODO: most of this code should be in blockstack.js
// Will remove most of this code once the wallet functionality is there instead.

const blockstack = require('blockstack')
const keychains = require('blockstack-keychains')
const bitcoin = require('bitcoinjs-lib')
const bip39 = require('bip39')
const bip32 = require('bip32')
const crypto = require('crypto')
const c32check = require('c32check')

import {
  getPrivateKeyAddress
} from './utils';

import {
  getMaxIDSearchIndex
} from './cli';

import type BIP32 from 'bip32';

export const STRENGTH = 128;   // 12 words

function toPrivkeyHex(k : Object) : string {
  return `${k.privateKey.toString('hex')}01`;
}

function walletFromMnemonic(mnemonic: string): blockstack.BlockstackWallet {
  const seed = bip39.mnemonicToSeed(mnemonic)
  return new blockstack.BlockstackWallet(bip32.fromSeed(seed))
}

function getNodePrivateKey(node: BIP32): string {
  return blockstack.ecPairToHexString(bitcoin.ECPair.fromPrivateKey(node.privateKey))
}

/*
 * Get the owner key information for a 12-word phrase, at a specific index.
 * @network (object) the blockstack network
 * @mnemonic (string) the 12-word phrase
 * @index (number) the account index
 * @version (string) the derivation version string
 *
 * Returns an object with:
 *    .privateKey (string) the hex private key
 *    .version (string) the version string of the derivation
 *    .idAddress (string) the ID-address
 */
export function getOwnerKeyInfo(network: Object,
                                mnemonic : string, 
                                index : number, 
                                version : string = 'v0.10-current') {

  const wallet = walletFromMnemonic(mnemonic);
  const identity = wallet.getIdentityAddressNode(index);
  const addr = network.coerceAddress(blockstack.BlockstackWallet.getAddressFromBIP32Node(identity));
  const privkey = getNodePrivateKey(identity);
  return {
    privateKey: privkey,
    version: version,
    index: index,
    idAddress: `ID-${addr}`,
  };
}

/*
 * Get the payment key information for a 12-word phrase.
 * @network (object) the blockstack network
 * @mnemonic (string) the 12-word phrase
 *
 * Returns an object with:
 *    .privateKey (string) the hex private key
 *    .address (string) the address of the private key
 */
export function getPaymentKeyInfo(network: Object, mnemonic : string) {
  const wallet = walletFromMnemonic(mnemonic);
  const privkey = wallet.getBitcoinPrivateKey(0);
  const addr = getPrivateKeyAddress(network, privkey);
  return {
    privateKey: privkey,
    address: {
      BTC: addr,
      STACKS: c32check.b58ToC32(addr),
    },
    index: 0
  };
}

/*
 * Find the index of an ID address, given the mnemonic.
 * Returns the index if found
 * Returns -1 if not found
 */
export function findIdentityIndex(network: Object, mnemonic: string, idAddress: string, maxIndex: ?number) {
  if (!maxIndex) {
    maxIndex = getMaxIDSearchIndex();
  }

  if (idAddress.substring(0,3) !== 'ID-') {
    throw new Error('Not an identity address');
  }

  const wallet = walletFromMnemonic(mnemonic);
  for (let i = 0; i < maxIndex; i++) {
    const identity = wallet.getIdentityAddressNode(i);
    const addr = blockstack.BlockstackWallet.getAddressFromBIP32Node(identity);

    if (network.coerceAddress(addr) ===
        network.coerceAddress(idAddress.slice(3))) {
      return i;
    }
  }

  return -1;
}

/*
 * Get the Gaia application key from a 12-word phrase
 * @network (object) the blockstack network
 * @mmemonic (string) the 12-word phrase
 * @idAddress (string) the ID-address used to sign in
 * @appDomain (string) the application's Origin
 *
 * Returns an object with
 *    .keyInfo (object) the app key info with the current derivation path 
 *      .privateKey (string) the app's hex private key
 *      .address (string) the address of the private key
 *    .legacyKeyInfo (object) the app key info with the legacy derivation path
 *      .privateKey (string) the app's hex private key
 *      .address (string) the address of the private key
 */
export function getApplicationKeyInfo(network: Object,
                                      mnemonic : string, 
                                      idAddress: string, 
                                      appDomain: string, 
                                      idIndex: ?number) {
  if (!idIndex) {
    idIndex = -1;
  }

  if (idIndex < 0) {
    idIndex = findIdentityIndex(network, mnemonic, idAddress);
    if (idIndex < 0) {
      throw new Error('Identity address does not belong to this keychain');
    }
  }

  const wallet = walletFromMnemonic(mnemonic);
  const identityOwnerAddressNode = wallet.getIdentityAddressNode(idIndex);
  const appsNode = blockstack.BlockstackWallet.getAppsNode(identityOwnerAddressNode);

  const appPrivateKey = blockstack.BlockstackWallet.getAppPrivateKey(
    appsNode.toBase58(), wallet.getIdentitySalt(), appDomain);
  const legacyAppPrivateKey = blockstack.BlockstackWallet.getLegacyAppPrivateKey(
    appsNode.toBase58(), wallet.getIdentitySalt(), appDomain);

  // TODO: figure out when we can start using the new derivation path
  const res = {
    keyInfo: {
      privateKey: 'TODO', // appPrivateKey,
      address: 'TODO', // getPrivateKeyAddress(network, `${appPrivateKey}01`)
    },
    legacyKeyInfo: {
      privateKey: legacyAppPrivateKey,
      address: getPrivateKeyAddress(network, `${legacyAppPrivateKey}01`)
    },
    ownerKeyIndex: idIndex
  };
  return res;
}

/*
 * Extract the "right" app key
 */
export function extractAppKey(
  network: Object,
  appKeyInfo: { keyInfo: { privateKey: string, address: string }, legacyKeyInfo: { privateKey : string, address: string } },
  appAddress?: string
) {
  if (appAddress) {
    if (network.coerceMainnetAddress(appKeyInfo.keyInfo.address) === network.coerceMainnetAddress(appAddress)) {
      return appKeyInfo.keyInfo.privateKey;
    }
    if (network.coerceMainnetAddress(appKeyInfo.legacyKeyInfo.address) === network.coerceMainnetAddress(appAddress)) {
      return appKeyInfo.legacyKeyInfo.privateKey;
    }
  }

  const appPrivateKey = (appKeyInfo.keyInfo.privateKey === 'TODO' || !appKeyInfo.keyInfo.privateKey ?
                         appKeyInfo.legacyKeyInfo.privateKey :
                         appKeyInfo.keyInfo.privateKey);
  return appPrivateKey;
}
