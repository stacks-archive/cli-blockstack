import blockstack from 'blockstack';
import express from 'express';
import crypto from 'crypto';

declare var jsontokens : any;
var jsontokens = require('jsontokens');

import winston from 'winston'
import logger from 'winston'

import {
  gaiaConnect,
  gaiaUploadProfileAll,
  makeAssociationToken,
  getGaiaAddressFromProfile
} from './data';

import {
  getApplicationKeyInfo,
  getOwnerKeyInfo,
  extractAppKey
} from './keys';

import {
  nameLookup,
  makeProfileJWT,
  getPublicKeyFromPrivateKey,
  canonicalPrivateKey,
} from './utils';

import {
   CLINetworkAdapter
} from './network';

import { 
  GaiaHubConfig
} from 'blockstack/lib/storage/hub';

export const SIGNIN_CSS = `
h1 { 
  font-family: monospace; 
  font-size: 24px; 
  font-style: normal; 
  font-variant: normal; 
  font-weight: 700; 
  line-height: 26.4px; 
} 
h3 { 
  font-family: monospace; 
  font-size: 14px; 
  font-style: normal; 
  font-variant: normal; 
  font-weight: 700; 
  line-height: 15.4px; 
}
p { 
  font-family: monospace; 
  font-size: 14px; 
  font-style: normal; 
  font-variant: normal; 
  font-weight: 400; 
  line-height: 20px; 
}
b {
  background-color: #e8e8e8;
}
pre { 
  font-family: monospace; 
  font-size: 13px; 
  font-style: normal; 
  font-variant: normal; 
  font-weight: 400; 
  line-height: 18.5714px;
}`

export const SIGNIN_HEADER = `<html><head><style>${SIGNIN_CSS}</style></head></body><h3>Blockstack CLI Sign-in</h3><br>`
export const SIGNIN_DESC = '<p>Sign-in request for <b>"{appName}"</b></p>'
export const SIGNIN_SCOPES = '<p>Requested scopes: <b>"{appScopes}"</b></p>'
export const SIGNIN_FMT_NAME = '<p><a href="{authRedirect}">{blockstackID}</a> ({idAddress})</p>'
export const SIGNIN_FMT_ID = '<p><a href="{authRedirect}">{idAddress}</a> (anonymous)</p>'
export const SIGNIN_FOOTER = '</body></html>'

export interface NamedIdentityType {
  name: string;
  idAddress: string;
  privateKey: string;
  index: number;
  profile: Object;
  profileUrl: string
};

interface AuthRequestType {
   jti: string;
   iat: number;
   exp: number;
   iss: null | string;
   public_keys: string[];
   domain_name: string;
   manifest_uri: string;
   redirect_uri: string;
   version: string;
   do_not_include_profile: boolean;
   supports_hub_url: boolean;
   scopes: string[]
};


// new ecdsa private key each time
const authTransitKey = crypto.randomBytes(32).toString('hex');
const authTransitPubkey = getPublicKeyFromPrivateKey(authTransitKey);
const authTransitNonce = crypto.randomBytes(32).toString('hex');


/*
 * Get the app private key
 */
function getAppPrivateKey(network: CLINetworkAdapter,
                          mnemonic: string,
                          id: NamedIdentityType,
                          appOrigin: string
): string {
  const appKeyInfo = getApplicationKeyInfo(network, mnemonic, id.idAddress, appOrigin, id.index);
  let appPrivateKey;
  try {
    const existingAppAddress = getGaiaAddressFromProfile(network, id.profile, appOrigin);
    appPrivateKey = extractAppKey(network, appKeyInfo, existingAppAddress);
  }
  catch (e) {
    appPrivateKey = extractAppKey(network, appKeyInfo);
  }

  return appPrivateKey;
}

/*
 * Make a sign-in link
 */
function makeSignInLink(network: CLINetworkAdapter,
                        authPort: number,
                        mnemonic: string,
                        authRequest: AuthRequestType,
                        hubUrl: string,
                        id: NamedIdentityType) : string {
  
  const appOrigin = authRequest.domain_name;
  const appKeyInfo = getApplicationKeyInfo(network, mnemonic, id.idAddress, appOrigin, id.index);
  const appPrivateKey = getAppPrivateKey(network, mnemonic, id, appOrigin);

  const associationToken = makeAssociationToken(appPrivateKey, id.privateKey)
  const authResponseTmp = blockstack.makeAuthResponse(
    id.privateKey,
    {},
    id.name,
    { email: null, profileUrl: id.profileUrl },
    null,
    appPrivateKey,
    undefined,
    authRequest.public_keys[0],
    hubUrl,
    blockstack.config.network.blockstackAPIUrl,
    associationToken
  );

  // pass along some helpful data from the authRequest
  const authResponsePayload = jsontokens.decodeToken(authResponseTmp).payload;
  let id_public = Object.assign({}, id);
  id_public.profile = {};
  id_public.privateKey = undefined;
    
  authResponsePayload.metadata = {
    id: id_public,
    profileUrl: id.profileUrl,
    appOrigin: appOrigin,
    redirect_uri: authRequest.redirect_uri,
    scopes: authRequest.scopes,
    salt: crypto.randomBytes(16).toString('hex'),
    nonce: authTransitNonce
    // fill in more CLI-specific fields here
  };

  const tokenSigner = new jsontokens.TokenSigner('ES256k', id.privateKey);
  const authResponse = tokenSigner.sign(authResponsePayload);

  return blockstack.updateQueryStringParameter(
    `http://localhost:${authPort}/signin`, 'authResponse', authResponse);
}

/*
 * Make the sign-in page
 */
function makeAuthPage(network: CLINetworkAdapter,
                      authPort: number,
                      mnemonic: string,
                      hubUrl: string,
                      manifest: any,
                      authRequest: AuthRequestType,
                      ids: Array<NamedIdentityType>
) : string {

  let signinBody = SIGNIN_HEADER
  let signinDescription = SIGNIN_DESC
    .replace(/{appName}/, manifest.name || "(Unknown app)");

  let signinScopes = SIGNIN_SCOPES
    .replace(/{appScopes}/, authRequest.scopes.length > 0
                            ? authRequest.scopes.join(", ")
                            : "(none)");

  signinBody = `${signinBody}${signinDescription}${signinScopes}`

  for (let i = 0; i < ids.length; i++) {
    let signinEntry
    if (ids[i].name) {
      signinEntry = SIGNIN_FMT_NAME
        .replace(/{authRedirect}/, makeSignInLink(
          network,
          authPort,
          mnemonic,
          authRequest,
          hubUrl,
          ids[i]))
        .replace(/{blockstackID}/, ids[i].name)
        .replace(/{idAddress}/, ids[i].idAddress);
    }
    else {
      signinEntry = SIGNIN_FMT_ID
        .replace(/{authRedirect}/, makeSignInLink(
          network,
          authPort,
          mnemonic,
          authRequest,
          hubUrl,
          ids[i]))
        .replace(/{idAddress}/, ids[i].idAddress);
    }

    signinBody = `${signinBody}${signinEntry}`;
  }

  signinBody = `${signinBody}${SIGNIN_FOOTER}`;
  return signinBody;
}


/*
 * Find all identity addresses that have names attached to them.
 * Fills in identities.
 */
function loadNamedIdentitiesLoop(network: CLINetworkAdapter, 
                                 mnemonic: string, 
                                 index: number, 
                                 identities: NamedIdentityType[]) : Promise<NamedIdentityType[]> {

  // 65536 is a ridiculously huge number
  if (index > 65536) {
    throw new Error('Too many names')
  }

  const keyInfo = getOwnerKeyInfo(network, mnemonic, index);
  return network.getNamesOwned(keyInfo.idAddress.slice(3))
    .then((nameList) => {
      if (nameList.length === 0) {
        // out of names 
        return identities;
      }
      for (let i = 0; i < nameList.length; i++) {
        identities.push({
          name: nameList[i],
          idAddress: keyInfo.idAddress,
          privateKey: keyInfo.privateKey,
          index: index,
          profile: {},
          profileUrl: ''
        } as NamedIdentityType);
      }
      return loadNamedIdentitiesLoop(network, mnemonic, index + 1, identities);
    });
}

/*
 * Load all named identities for a mnemonic.
 * Keep loading until we find an ID-address that does not have a name.
 */
export function loadNamedIdentities(network: CLINetworkAdapter, mnemonic: string) 
  : Promise<Array<NamedIdentityType>> {
  return loadNamedIdentitiesLoop(network, mnemonic, 0, []);
}


/*
 * Generate identity info for an unnamed ID
 */
function loadUnnamedIdentity(network: CLINetworkAdapter, mnemonic: string, index: number): NamedIdentityType {
  const keyInfo = getOwnerKeyInfo(network, mnemonic, index);
  const idInfo = {
    name: '',
    idAddress: keyInfo.idAddress,
    privateKey: keyInfo.privateKey,
    index: index,
    profile: {},
    profileUrl: ''
  };
  return idInfo;
}

/*
 * Send a JSON HTTP response
 */
function sendJSON(res: express.Response, data: Object, statusCode: number) {
  logger.info(`Respond ${statusCode}: ${JSON.stringify(data)}`);
  res.writeHead(statusCode, {'Content-Type' : 'application/json'})
  res.write(JSON.stringify(data))
  res.end()
}


/*
 * Get all of a 12-word phrase's identities, profiles, and Gaia connections.
 * Returns a Promise to an Array of NamedIdentityType instances.
 *
 * NOTE: should be the *only* promise chain running!
 */
function getIdentityInfo(network: CLINetworkAdapter, mnemonic: string, appGaiaHub: string, profileGaiaHub: string) 
  : Promise<NamedIdentityType[]> {

  let identities : NamedIdentityType[] = [];
  network.setCoerceMainnetAddress(true);    // for lookups in regtest
  
  // load up all of our identity addresses and profile URLs
  const identitiesPromise = loadNamedIdentities(network, mnemonic)
    .then((ids) => {
      const nameInfoPromises = [];
      for (let i = 0; i < ids.length; i++) {
        const nameInfoPromise = nameLookup(network, ids[i].name, true)
          .catch(() => null);

        nameInfoPromises.push(nameInfoPromise);
      }

      identities = ids;
      return Promise.all(nameInfoPromises);
    })
    .then((nameDatas) => {
      network.setCoerceMainnetAddress(false);
      nameDatas = nameDatas.filter((p) => p !== null && p !== undefined);

      for (let i = 0; i < nameDatas.length; i++) {
        if (nameDatas[i].hasOwnProperty('error') && nameDatas[i].error) {
          // no data for this name 
          identities[i].profileUrl = '';
        }
        else {
          identities[i].profileUrl = nameDatas[i].profileUrl;
          identities[i].profile = nameDatas[i].profile;
        }
      }

      const nextIndex = identities.length + 1

      // ignore identities with no data
      identities = identities.filter((id) => !!id.profileUrl);

      // add in the next non-named identity
      identities.push(loadUnnamedIdentity(network, mnemonic, nextIndex))
      return identities;
    })
    .catch((e) => {
      network.setCoerceMainnetAddress(false);
      throw e;
    });

  return identitiesPromise;
}


/*
 * Handle GET /auth?authRequest=...
 * If the authRequest is verifiable and well-formed, and if we can fetch the application
 * manifest, then we can render an auth page to the user.
 * Serves back the sign-in page on success.
 * Serves back an error page on error.
 * Returns a Promise that resolves to nothing.
 *
 * NOTE: should be the *only* promise chain running!
 */
export function handleAuth(network: CLINetworkAdapter,
                           mnemonic: string,
                           gaiaHubUrl: string,
                           profileGaiaHub: string,
                           port: number, 
                           req: express.Request,
                           res: express.Response
) : Promise<any> {

  const authToken = req.query.authRequest;
  if (!authToken) {
     return Promise.resolve().then(() => {
       sendJSON(res, { error: 'No authRequest given' }, 400);
     });
  }
 
  let errorMsg : string = '';
  let identities : NamedIdentityType[] = [];
  return getIdentityInfo(network, mnemonic, gaiaHubUrl, profileGaiaHub)
    .then((ids) => {
      identities = ids;
      errorMsg = 'Unable to verify authentication token';
      return blockstack.verifyAuthRequest(authToken);
    })
    .then((valid) => {
      if (!valid) {
        errorMsg = 'Invalid authentication token: could not verify';
        throw new Error(errorMsg);
      }
      errorMsg = 'Unable to fetch app manifest';
      return blockstack.fetchAppManifest(authToken);
    })
    .then((appManifest) => {
      const decodedAuthToken = jsontokens.decodeToken(authToken);
      const decodedAuthPayload = decodedAuthToken.payload;
      if (!decodedAuthPayload) {
        errorMsg = 'Invalid authentication token: no payload';
        throw new Error(errorMsg);
      }

      // make sign-in page
      const authPage = makeAuthPage(
        network, port, mnemonic, gaiaHubUrl, appManifest, decodedAuthPayload, identities);

      res.writeHead(200, {'Content-Type': 'text/html', 'Content-Length': authPage.length});
      res.write(authPage);
      res.end();
      return;
    })
    .catch((e) => {
      if (!errorMsg) {
        errorMsg = e.message;
      }

      logger.error(e)
      logger.error(errorMsg)
      sendJSON(res, { error: `Unable to authenticate app request: ${errorMsg}` }, 400);
      return;
    });
}

/*
 * Update a named identity's profile with new app data, if necessary.
 * Indicates whether or not the profile was changed.
 */
function updateProfileApps(network: CLINetworkAdapter, 
                          id: NamedIdentityType, 
                          appOrigin: string, 
                          appGaiaConfig: GaiaHubConfig,
                          profile?: any
): Promise<{ profile: any, changed: boolean }> {

  let needProfileUpdate = false;

  // go get the profile from the profile URL in the id
  const profilePromise = Promise.resolve().then(() => {
    if (profile === null || profile === undefined) {
      return nameLookup(network, id.name)
        .catch((e) => null);
    } else {
      return { profile: profile };
    }
  });

  return profilePromise.then((profileData) => {
    if (profileData) {
      profile = profileData.profile;
    }

    if (!profile) {
      // instantiate 
      logger.debug(`Profile for ${id.name} is ${JSON.stringify(profile)}`);
      logger.debug(`Instantiating profile for ${id.name}`);
      needProfileUpdate = true;
      profile = {
        'type': '@Person',
        'account': [],
        'apps': {},
      };
    }

    // do we need to update the Gaia hub read URL in the profile?
    if (profile.apps === null || profile.apps === undefined) {
      needProfileUpdate = true;

      logger.debug(`Adding multi-reader Gaia links to profile for ${id.name}`);
      profile.apps = {};
    }

    const gaiaPrefix = `${appGaiaConfig.url_prefix}${appGaiaConfig.address}/`;

    if (!profile.apps.hasOwnProperty(appOrigin) || !profile.apps[appOrigin]) {
      needProfileUpdate = true;
      logger.debug(`Setting Gaia read URL ${gaiaPrefix} for ${appOrigin} ` +
        `in profile for ${id.name}`);

      profile.apps[appOrigin] = gaiaPrefix;
    }
    else if (!profile.apps[appOrigin].startsWith(gaiaPrefix)) {
      needProfileUpdate = true;
      logger.debug(`Overriding Gaia read URL for ${appOrigin} from ${profile.apps[appOrigin]} ` +
        `to ${gaiaPrefix} in profile for ${id.name}`);

      profile.apps[appOrigin] = gaiaPrefix;
    }

    return { profile, changed: needProfileUpdate };
  })
}

/*
 * Updates a named identitie's profile's API settings, if necessary.
 * Indicates whether or not the profile data changed.
 */
function updateProfileAPISettings(network: CLINetworkAdapter,
                                  id: NamedIdentityType,
                                  appGaiaConfig: GaiaHubConfig,
                                  profile?: any
): Promise<{ profile: any, changed: boolean }> {

  let needProfileUpdate = false;

  // go get the profile from the profile URL in the id
  const profilePromise = Promise.resolve().then(() => {
    if (profile === null || profile === undefined) {
      return nameLookup(network, id.name)
        .catch((e) => null);
    }
    else {
      return { profile: profile };
    }
  });
      
  return profilePromise.then((profileData) => {
    if (profileData) {
      profile = profileData.profile;
    }

    if (!profile) {
      // instantiate
      logger.debug(`Profile for ${id.name} is ${JSON.stringify(profile)}`);
      logger.debug(`Instantiating profile for ${id.name}`);
      needProfileUpdate = true;
      profile = {
        'type': '@Person',
        'account': [],
        'api': {},
      };
    }

    // do we need to update the API settings in the profile?
    if (profile.api === null || profile.api === undefined) {
      needProfileUpdate = true;

      logger.debug(`Adding API settings to profile for ${id.name}`);
      profile.api = {
        gaiaHubConfig: {
          url_prefix: appGaiaConfig.url_prefix
        },
        gaiaHubUrl: appGaiaConfig.server
      };
    }

    if (!profile.hasOwnProperty('api') || !profile.api.hasOwnProperty('gaiaHubConfig') ||
        !profile.api.gaiaHubConfig.hasOwnProperty('url_prefix') || !profile.api.gaiaHubConfig.url_prefix ||
        !profile.api.hasOwnProperty('gaiaHubUrl') || !profile.api.gaiaHubUrl) {

      logger.debug(`Existing profile for ${id.name} is ${JSON.stringify(profile)}`);
      logger.debug(`Updating API settings to profile for ${id.name}`);
      profile.api = {
        gaiaHubConfig: {
          url_prefix: appGaiaConfig.url_prefix
        },
        gaiaHubUrl: appGaiaConfig.server
      };
    }

    return { profile, changed: needProfileUpdate };
  })
}

/*
 * Handle GET /signin?encAuthResponse=...
 * Takes an encrypted authResponse from the page generated on GET /auth?authRequest=....,
 * verifies it, updates the name's profile's app's entry with the latest Gaia
 * hub information (if necessary), and redirects the user back to the application.
 *
 * If adminKey is given, then the new app private key will be automatically added
 * as an authorized writer to the Gaia hub.
 *
 * Redirects the user on success.
 * Sends the user an error page on failure.
 * Returns a Promise that resolves to nothing.
 */
export function handleSignIn(network: CLINetworkAdapter, 
                             mnemonic: string,
                             appGaiaHub: string, 
                             profileGaiaHub: string,
                             req: express.Request, 
                             res: express.Response
): Promise<any> {
  
  const authResponseQP = req.query.authResponse;
  if (!authResponseQP) {
    return Promise.resolve().then(() => {
      sendJSON(res, { error: 'No authResponse given' }, 400);
    });
  }
  const nameLookupUrl = `${network.blockstackAPIUrl}/v1/names/`;

  let errorMsg : string = '';
  let errorStatusCode = 400;
  let authResponsePayload : any;
    
  let id : NamedIdentityType;
  let profileUrl : string;
  let appOrigin : string;
  let redirectUri : string;
  let scopes : string[];
  let authResponse : string;
  let hubConfig : GaiaHubConfig;
  let needProfileAPIUpdate = false;
  let profileAPIUpdate : boolean;

  return Promise.resolve().then(() => {
    return blockstack.verifyAuthResponse(authResponseQP, nameLookupUrl);
  })
  .then((valid) => {
    if (!valid) {
      errorMsg = `Unable to verify authResponse token ${authResponseQP}`;
      throw new Error(errorMsg);
    }

    const authResponseToken = jsontokens.decodeToken(authResponseQP);
    authResponsePayload = authResponseToken.payload;

    id = authResponsePayload.metadata.id;
    profileUrl = authResponsePayload.metadata.profileUrl;
    appOrigin = authResponsePayload.metadata.appOrigin;
    redirectUri = authResponsePayload.metadata.redirect_uri;
    scopes = authResponsePayload.metadata.scopes;
    const nonce = authResponsePayload.metadata.nonce;

    if (nonce != authTransitNonce) {
      throw new Error('Invalid auth response: not generated by this authenticator')
    }

    // restore
    id.privateKey = getOwnerKeyInfo(network, mnemonic, id.index).privateKey;

    const appPrivateKey = getAppPrivateKey(network, mnemonic, id, appOrigin);

    // remove sensitive (CLI-specific) information
    authResponsePayload.metadata = {
      profileUrl: profileUrl
    };

    authResponse = new jsontokens.TokenSigner('ES256K', id.privateKey).sign(authResponsePayload);
    
    logger.debug(`App ${appOrigin} requests scopes ${JSON.stringify(scopes)}`);

    // connect to the app gaia hub
    return gaiaConnect(network, appGaiaHub, appPrivateKey);
  })
  .then((appHubConfig) => {
    hubConfig = appHubConfig;
    return updateProfileAPISettings(network, id, hubConfig);
  })
  .then((newProfileData) => {
    needProfileAPIUpdate = newProfileData.changed;
    profileAPIUpdate = newProfileData.profile;
    return updateProfileApps(network, id, appOrigin, hubConfig, profileAPIUpdate);
  })
  .then((newProfileData) => {
    const profile = newProfileData.profile;
    const needProfileSigninUpdate = newProfileData.changed && scopes.includes('store_write');

    logger.debug(`Resulting profile for ${id.name} is ${JSON.stringify(profile)}`);

    // sign and replicate new profile if we need to.
    // otherwise do nothing 
    if (needProfileSigninUpdate) {
      logger.debug(`Upload new profile with new sign-in data to ${profileGaiaHub}`);
      const profileJWT = makeProfileJWT(profile, id.privateKey);
      return gaiaUploadProfileAll(
        network, [profileGaiaHub], profileJWT, id.privateKey, id.name);
    }
    else if (needProfileAPIUpdate) {
      // API settings changed, but we won't be adding an app entry
      logger.debug(`Upload new profile with new API settings to ${profileGaiaHub}`);
      const profileJWT = makeProfileJWT(profileAPIUpdate, id.privateKey);
      return gaiaUploadProfileAll(
        network, [profileGaiaHub], profileJWT, id.privateKey, id.name);
    }
    else {
      logger.debug(`Gaia read URL for ${appOrigin} is ${profile.apps[appOrigin]}`);
      return { dataUrls: [], error: null };
    }
  })
  .then((gaiaUrls) => {
    if (gaiaUrls.hasOwnProperty('error') && gaiaUrls.error) {
      errorMsg = `Failed to upload new profile: ${gaiaUrls.error}`;
      errorStatusCode = 502;
      throw new Error(errorMsg);
    }

    // success!
    // redirect to application
    logger.debug(`Handled sign-in to ${appOrigin} using ${id.name}`);
    const appUri = blockstack.updateQueryStringParameter(redirectUri, 'authResponse', authResponse);

    logger.info(`Redirect to ${appUri}`);
    res.writeHead(302, {'Location': appUri});
    res.end();
    return;
  })
  .catch((e) => {
    logger.error(e);
    logger.error(errorMsg);
    sendJSON(res, { error: `Unable to process signin request: ${errorMsg}` }, errorStatusCode);
    return;
  });
}
