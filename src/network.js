/* @flow */

const blockstack = require('blockstack');
const Promise = require('bluebird');
const bigi = require('bigi');
const bitcoin = require('bitcoinjs-lib');

Promise.onPossiblyUnhandledRejection(function(error){
    throw error;
});

const SATOSHIS_PER_BTC = 1e8

/*
 * Adapter class that allows us to use data obtained
 * from the CLI.
 */
export class CLINetworkAdapter extends blockstack.network.BlockstackNetwork {
  consensusHash: string | null
  feeRate: number | null
  namespaceBurnAddress: string | null
  priceToPay: number | null
  priceUnits: string | null
  gracePeriod: number | null

  constructor(network: blockstack.network.BlockstackNetwork, opts: Object) {
    const optsDefault = {
      consensusHash: null,
      feeRate: null,
      namesspaceBurnAddress: null,
      priceToPay: null,
      priceUnits: null,
      receiveFeesPeriod: null,
      gracePeriod: null,
      altAPIUrl: network.blockstackAPIUrl,
      altTransactionBroadcasterUrl: network.broadcastServiceUrl,
      nodeAPIUrl: null
    }

    opts = Object.assign({}, optsDefault, opts);

    super(opts.altAPIUrl, opts.altTransactionBroadcasterUrl, network.btc, network.layer1)
    this.consensusHash = opts.consensusHash
    this.feeRate = opts.feeRate
    this.namespaceBurnAddress = opts.namespaceBurnAddress
    this.priceToPay = opts.priceToPay
    this.priceUnits = opts.priceUnits
    this.receiveFeesPeriod = opts.receiveFeesPeriod
    this.gracePeriod = opts.gracePeriod
    this.nodeAPIUrl = opts.nodeAPIUrl
    
    this.optAlwaysCoerceAddress = false
  }

  isMainnet() : boolean {
    return this.layer1.pubKeyHash === bitcoin.networks.bitcoin.pubKeyHash
  }

  isTestnet() : boolean {
    return this.layer1.pubKeyHash === bitcoin.networks.testnet.pubKeyHash
  }

  setCoerceMainnetAddress(value: boolean) {
    this.optAlwaysCoerceAddress = value
  }

  coerceMainnetAddress(address: string) : string {
    const addressInfo = bitcoin.address.fromBase58Check(address)
    const addressHash = addressInfo.hash
    const addressVersion = addressInfo.version
    let newVersion = 0

    if (addressVersion === this.layer1.pubKeyHash) {
      newVersion = 0
    }
    else if (addressVersion === this.layer1.scriptHash) {
      newVersion = 5
    }
    return bitcoin.address.toBase58Check(addressHash, newVersion)
  }

  getFeeRate() : Promise<number> {
    if (this.feeRate) {
      // override with CLI option
      return Promise.resolve(this.feeRate)
    }
    if (this.isTestnet()) {
      // in regtest mode 
      return Promise.resolve(Math.floor(0.00001000 * SATOSHIS_PER_BTC))
    }
    return super.getFeeRate()
  }

  getConsensusHash() {
    // override with CLI option
    if (this.consensusHash) {
      return new Promise((resolve) => resolve(this.consensusHash))
    }
    return super.getConsensusHash()
  }

  getGracePeriod() {
    if (this.gracePeriod) {
      return this.gracePeriod
    }
    return super.getGracePeriod()
  }

  getNamePrice(name: string) {
    // override with CLI option 
    if (this.priceUnits && this.priceToPay) {
      return new Promise((resolve) => resolve({
        units: String(this.priceUnits),
        amount: bigi.fromByteArrayUnsigned(String(this.priceToPay))
      }))
    }
    return super.getNamePrice(name)
      .then((priceInfo) => {
        // use v2 scheme
        if (!priceInfo.units) {
          priceInfo = {
            units: 'BTC',
            amount: bigi.fromByteArrayUnsigned(String(priceInfo))
          }
        }
        return priceInfo;
      })
  }

  getNamespacePrice(namespaceID: string) {
    // override with CLI option 
    if (this.priceUnits && this.priceToPay) {
      return new Promise((resolve) => resolve({
        units: String(this.priceUnits),
        amount: bigi.fromByteArrayUnsigned(String(this.priceToPay))
      }))
    }
    return super.getNamespacePrice(namespaceID)
      .then((priceInfo) => {
        // use v2 scheme
        if (!priceInfo.units) {
          priceInfo = {
            units: 'BTC',
            amount: bigi.fromByteArrayUnsigned(String(priceInfo))
          }
        }
        return priceInfo;
      })
  }

  getNamespaceBurnAddress(namespace: string, useCLI: ?boolean = true) {
    // override with CLI option
    if (this.namespaceBurnAddress && useCLI) {
      return new Promise((resolve) => resolve(this.namespaceBurnAddress))
    }

    return Promise.all([
      fetch(`${this.blockstackAPIUrl}/v1/namespaces/${namespace}`),
      this.getBlockHeight()
    ])
    .then(([resp, blockHeight]) => {
      if (resp.status === 404) {
        throw new Error(`No such namespace '${namespace}'`)
      } else if (resp.status !== 200) {
        throw new Error(`Bad response status: ${resp.status}`)
      } else {
        return Promise.all([resp.json(), blockHeight])
      }
    })
    .then(([namespaceInfo, blockHeight]) => {
      let address = '1111111111111111111114oLvT2' // default burn address
      if (namespaceInfo.version === 2) {
        // pay-to-namespace-creator if this namespace is less than $receiveFeesPeriod blocks old
        if (namespaceInfo.reveal_block + this.receiveFeesPeriod > blockHeight) {
          address = namespaceInfo.address
        }
      }
      return address
    })
    .then(address => this.coerceAddress(address))
  }

  getNameInfo(name: string) {
    // optionally coerce addresses
    return super.getNameInfo(name)
      .then((nameInfo) => {
        if (this.optAlwaysCoerceAddress) {
          nameInfo = Object.assign(nameInfo, {
            'address': this.coerceMainnetAddress(nameInfo.address)
          })
        }

        return nameInfo
      })
  }


  getBlockchainNameRecord(name: string) : Promise<*> {
    // TODO: send to blockstack.js
    const url = `${this.blockstackAPIUrl}/v1/blockchains/bitcoin/names/${name}`
    return fetch(url)
      .then((resp) => {
        if (resp.status !== 200) {
          throw new Error(`Bad response status: ${resp.status}`)
        }
        else {
          return resp.json();
        }
      })
      .then((nameInfo) => {
        // coerce all addresses
        let fixedAddresses = {}
        for (let addrAttr of ['address', 'importer_address', 'recipient_address']) {
          if (nameInfo.hasOwnProperty(addrAttr) && nameInfo[addrAttr]) {
            fixedAddresses[addrAttr] = this.coerceAddress(nameInfo[addrAttr])
          }
        }
        return Object.assign(nameInfo, fixedAddresses)
    })
  }

  getNameHistory(name: string, page: number) : Promise<*> { 
    // TODO: send to blockstack.js 
    const url = `${this.blockstackAPIUrl}/v1/names/${name}/history?page=${page}`
    return fetch(url)
      .then((resp) => {
        if (resp.status !== 200) {
          throw new Error(`Bad response status: ${resp.status}`)
        }
        return resp.json()
      })
      .then((historyInfo) => {
        // coerce all addresses 
        let fixedHistory = {}
        for (let historyBlock of Object.keys(historyInfo)) {
          let fixedHistoryList = []
          for (let historyEntry of historyInfo[historyBlock]) {
            let fixedAddresses = {}
            let fixedHistoryEntry = null 
            for (let addrAttr of ['address', 'importer_address', 'recipient_address']) {
              if (historyEntry.hasOwnProperty(addrAttr) && historyEntry[addrAttr]) {
                fixedAddresses[addrAttr] = this.coerceAddress(historyEntry[addrAttr])
              }
            }
            fixedHistoryEntry = Object.assign(historyEntry, fixedAddresses)
            fixedHistoryList.push(fixedHistoryEntry)
          }
          fixedHistory[historyBlock] = fixedHistoryList
        }
        return fixedHistory
      })
  }
}

/*
 * Instantiate a network using settings from the config file.
 */
export function getNetwork(configData: Object, regTest: boolean) 
  : blockstack.network.BlockstackNetwork {
  if (regTest) {
    const network = new blockstack.network.LocalRegtest(
      configData.blockstackAPIUrl, configData.broadcastServiceUrl, 
      new blockstack.network.BitcoindAPI(configData.utxoServiceUrl,
        { username: 'blockstack', password: 'blockstacksystem' }))

    return network
  } else {
    const network = new blockstack.network.BlockstackNetwork(
      configData.blockstackAPIUrl, configData.broadcastServiceUrl,
      new blockstack.network.BlockchainInfoApi(configData.utxoServiceUrl))

    return network
  }
}
  
