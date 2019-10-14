import * as blockstack from 'blockstack';
import * as triplesec from 'triplesec';

export function encryptBackupPhrase(plaintextBuffer: string, password: string) : Promise<Buffer> {
  return blockstack.encryptMnemonic(plaintextBuffer, password);
}

export function decryptBackupPhrase(dataBuffer: string | Buffer, password: string) : Promise<string> {
  return blockstack.decryptMnemonic(dataBuffer, password, triplesec.decrypt);
}

