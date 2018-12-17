/* @flow */

import blockstack from 'blockstack'

export function encryptBackupPhrase(plaintextBuffer: Buffer, password: string) : Promise<Buffer> {
  return blockstack.encryptMnemonic(plaintextBuffer, password);
}

export function decryptBackupPhrase(dataBuffer: Buffer, password: string) : Promise<string> {
  return blockstack.decryptMnemonic(dataBuffer, password);
}

