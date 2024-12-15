/**
 * @file src/parse-siwe.js
 * @author Lowell D. Thomas <ldt@sabnf.com>
 */
import { Parser } from './parser.js';
import { default as Grammar } from './grammar.js';
import { cb } from './callbacks.js';
import { isERC55, toERC55 } from './keccak256.js';
export { parseSiweMessage, isUri, siweObjectToString };

/**
 * Parses an [ERC-4361: Sign-In with Ethereum](https://eips.ethereum.org/EIPS/eip-4361) 
 * message to an object with the message components.
 *
 * @param {string} msg the ERC-4361 message
 * @param {string} erc55 controls [ERC-55](https://eips.ethereum.org/EIPS/eip-55) processing of the message address<br>
 *   - 'validate' - (default) parser fails if address is not in ERC-55 encoding
 *   - 'convert'  - parser will convert the address to ERC-55 encoding
 *   - 'other'    - (actually, any value other than 'validate', 'convert' or undefined) parser ignores ERC-55 encoding
 * @returns An siwe message object or throws exception with instructive message on format error.<br>
 * e.g. message
 * ````
example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

Valid statement

URI: https://example.com/login
Version: 1
Chain ID: 123456789
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Request ID: someRequestId
Resources:
- ftp://myftpsite.com/
- https://example.com/my-web2-claim.json
 * ````
* returns object, obj:
 * ````
  obj.scheme = undefined
  obj.domain = 'example.com:80'
  obj.address = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2'
  obj.statement = 'Valid statement'
  obj.uri = 'https://example.com/login'
  obj.version = 1
  obj.chainId = 123456789
  obj.nonce = '32891756'
  obj.issuedAt = '2021-09-30T16:25:24Z'
  obj.expirationTime = undefined
  obj.notBefore = undefined
  obj.requestId = 'someRequestId'
  obj.resources = [ 'ftp://myftpsite.com/', 'https://example.com/my-web2-claim.json' ]
* ````
 */
function parseSiweMessage(msg, erc55 = 'validate') {
  const fname = 'parseSiweMessage: ';
  if (typeof msg !== 'string') {
    throw new Error('SiweParser: input message must be of type string');
  }
  const p = new Parser();
  const g = new Grammar();

  // set the parser's callback functions
  p.callbacks['ffscheme'] = cb.ffscheme;
  p.callbacks['fdomain'] = cb.fdomain;
  p.callbacks['faddress'] = cb.faddress;
  p.callbacks['fstatement'] = cb.fstatement;
  p.callbacks['furi'] = cb.furi;
  p.callbacks['fnonce'] = cb.fnonce;
  p.callbacks['fversion'] = cb.fversion;
  p.callbacks['fchain-id'] = cb.fchainId;
  p.callbacks['fissued-at'] = cb.fissuedAt;
  p.callbacks['fexpiration-time'] = cb.fexpirationTime;
  p.callbacks['fnot-before'] = cb.fnotBefore;
  p.callbacks['frequest-id'] = cb.frequestId;
  p.callbacks['fresources'] = cb.fresources;
  p.callbacks['fresource'] = cb.fresource;
  p.callbacks['empty-statement'] = cb.emptyStatement;
  p.callbacks['no-statement'] = cb.noStatement;
  p.callbacks['actual-statement'] = cb.actualStatment;
  p.callbacks['pre-uri'] = cb.preUri;
  p.callbacks['pre-version'] = cb.preVersion;
  p.callbacks['pre-chain-id'] = cb.preChainId;
  p.callbacks['pre-nonce'] = cb.preNonce;
  p.callbacks['pre-issued-at'] = cb.preIssuedAt;
  // URI callbacks
  p.callbacks['uri'] = cb.URI;
  p.callbacks['scheme'] = cb.scheme;
  p.callbacks['userinfo-at'] = cb.userinfo;
  p.callbacks['host'] = cb.host;
  p.callbacks['IP-literal'] = cb.ipLiteral;
  p.callbacks['port'] = cb.port;
  p.callbacks['path-abempty'] = cb.pathAbempty;
  p.callbacks['path-absolute'] = cb.pathAbsolute;
  p.callbacks['path-rootless'] = cb.pathRootless;
  p.callbacks['path-empty'] = cb.pathEmpty;
  p.callbacks['query'] = cb.query;
  p.callbacks['fragment'] = cb.fragment;
  p.callbacks['IPv4address'] = cb.ipv4;
  p.callbacks['nodcolon'] = cb.nodcolon;
  p.callbacks['dcolon'] = cb.dcolon;
  p.callbacks['h16'] = cb.h16;
  p.callbacks['h16c'] = cb.h16;
  p.callbacks['h16n'] = cb.h16;
  p.callbacks['h16cn'] = cb.h16;
  p.callbacks['dec-octet'] = cb.decOctet;
  p.callbacks['dec-digit'] = cb.decDigit;

  // BEGIN: some parser helper functions
  function validateDateTime(time, name = 'unknown') {
    const ret = p.parse(g, 'date-time', time);
    if (!ret.success || isNaN(Date.parse(time))) {
      throw new Error(`${fname}invalid date time: ${name} not date time string format: ${time}`);
    }
  }
  function validInt(i) {
    const valid = parseInt(i, 10);
    if (isNaN(valid)) {
      throw new Error(`${fname}invalid integer: not a number: ${i}`);
    } else if (valid === Infinity) {
      throw new Error(`${fname}invalid integer: Infinity: ${i}`);
    }
    return valid;
  }

  // Validates an RFC 3986 URI.
  // returns true if the URI is valid, false otherwise
  function isUri(URI) {
    const uriData = {};
    ret = p.parse(g, 'uri', URI, uriData);
    return ret.success;
  }
  // END: some parser helper functions

  // first pass parse of the message
  // capture all the message parts, then validate them one-by-one later
  let data = { error: false };
  let ret;
  ret = p.parse(g, 'siwe-first-pass', msg, data);
  if (data.error) {
    throw new Error(`${fname}invalid siwe message: ${data.error}`);
  }
  if (!ret.success) {
    throw new Error(
      `${fname}invalid siwe message: carefully check message syntax, especially after required "Issued At: "\n${JSON.stringify(
        ret
      )}`
    );
  }

  if (data.fscheme) {
    // validate the scheme
    ret = p.parse(g, 'scheme', data.fscheme, {});
    if (!ret.success) {
      throw new Error(`${fname}invalid scheme: ${data.fscheme}`);
    }
  }

  // validate the domain
  ret = p.parse(g, 'authority', data.fdomain, {});
  if (!ret.success) {
    throw new Error(`${fname}invalid domain: ${data.fdomain}`);
  }

  // validate the address
  ret = p.parse(g, 'address', data.faddress);
  if (!ret.success) {
    throw new Error(`${fname}invalid address: ${data.faddress}`);
  }
  if (erc55 == 'validate') {
    // address must be ERC55 format
    if (!isERC55(data.faddress)) {
      throw new Error(
        `${fname}invalid ERC-55 format address: 'validate' specified, MUST be ERC55-conformant: ${data.faddress}`
      );
    }
  } else if (erc55 === 'convert') {
    // convert address to ERC55 format
    data.faddress = toERC55(data.faddress);
  }
  // else for any other value of erc55 no further action on the address is taken

  // validate the statement
  if (data.fstatement !== undefined && data.fstatement !== '') {
    ret = p.parse(g, 'statement', data.fstatement);
    if (!ret.success) {
      throw new Error(`${fname}invalid statement: ${data.fstatement}`);
    }
  }

  // validate the URI
  if (!isUri(data.furi)) {
    throw new Error(`${fname}invalid URI: ${data.furi}`);
  }

  // validate the version
  ret = p.parse(g, 'version', data.fversion);
  if (!ret.success) {
    throw new Error(`${fname}invalid Version: ${data.fversion}`);
  }
  data.fversion = validInt(data.fversion);

  // validate the chain-id
  ret = p.parse(g, 'chain-id', data.fchainId);
  if (!ret.success) {
    throw new Error(`${fname}invalid Chain ID: ${data.fchainId}`);
  }
  data.fchainId = validInt(data.fchainId);

  // validate nonce
  ret = p.parse(g, 'nonce', data.fnonce);
  if (!ret.success) {
    throw new Error(`${fname}invalid Nonce: ${data.fnonce}`);
  }

  // validate the date times
  validateDateTime(data.fissuedAt, 'Issued At');
  if (data.fexpirationTime) {
    validateDateTime(data.fexpirationTime, 'Expiration Time');
  }
  if (data.fnotBefore) {
    validateDateTime(data.fnotBefore, 'Not Before');
  }

  // validate request-id
  if (data.frequestId !== undefined && data.frequestId !== '') {
    ret = p.parse(g, 'request-id', data.frequestId);
    if (!ret.success) {
      throw new Error(`${fname}invalid Request ID: i${data.frequestId}`);
    }
  }

  // validate all resource URIs, if any
  if (data.fresources && data.fresources.length) {
    for (let i = 0; i < data.fresources.length; i++) {
      if (!isUri(data.fresources[i])) {
        throw new Error(`${fname}invalid resource URI [${i}]: ${data.fresources[i]}`);
      }
    }
  }

  // by now all first-pass values (e.g. fscheme) have been validated
  const o = {};
  o.scheme = data.fscheme;
  o.domain = data.fdomain;
  o.address = data.faddress;
  o.statement = data.fstatement;
  o.uri = data.furi;
  o.version = data.fversion;
  o.chainId = data.fchainId;
  o.nonce = data.fnonce;
  o.issuedAt = data.fissuedAt;
  o.expirationTime = data.fexpirationTime;
  o.notBefore = data.fnotBefore;
  o.requestId = data.frequestId;
  o.resources = undefined;
  if (data.fresources) {
    o.resources = [];
    for (let i = 0; i < data.fresources.length; i++) {
      o.resources.push(data.fresources[i]);
    }
  }
  return o;
}

/**
 * Parses a Uniform Resource Identifier (URI) defined in [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986).
 *
 * @param {string} URI the URI to parse
 * @returns `false` if the URI is invalid, otherwise a URI object. e.g.<br>
 * ````
 * const obj = isUri('uri://user:pass@example.com:123/one/two.three?q1=a1&q2=a2#body');
 * ````
 * returns:
 * ````
 * obj.scheme = 'uri'
 * obj.userinfo = 'user:pass'
 * obj.host = 'example.com',
 * obj.port = 123,
 * obj.path = '/one/two.three',
 * obj.query = 'q1=a1&q2=a2',
 * obj.fragment = 'body'
 * ````
 */
function isUri(URI) {
  const p = new Parser();
  const g = new Grammar();
  const uriData = {};
  p.callbacks['uri'] = cb.URI;
  p.callbacks['scheme'] = cb.scheme;
  p.callbacks['userinfo-at'] = cb.userinfo;
  p.callbacks['host'] = cb.host;
  p.callbacks['IP-literal'] = cb.ipLiteral;
  p.callbacks['port'] = cb.port;
  p.callbacks['path-abempty'] = cb.pathAbempty;
  p.callbacks['path-absolute'] = cb.pathAbsolute;
  p.callbacks['path-rootless'] = cb.pathRootless;
  p.callbacks['path-empty'] = cb.pathEmpty;
  p.callbacks['query'] = cb.query;
  p.callbacks['fragment'] = cb.fragment;
  p.callbacks['IPv4address'] = cb.ipv4;
  p.callbacks['nodcolon'] = cb.nodcolon;
  p.callbacks['dcolon'] = cb.dcolon;
  p.callbacks['h16'] = cb.h16;
  p.callbacks['h16c'] = cb.h16;
  p.callbacks['h16n'] = cb.h16;
  p.callbacks['h16cn'] = cb.h16;
  p.callbacks['dec-octet'] = cb.decOctet;
  p.callbacks['dec-digit'] = cb.decDigit;
  const ret = p.parse(g, 'uri', URI, uriData);
  if (!ret.success) {
    return false;
  }
  const uriObject = {
    uri: uriData['uri'],
    scheme: uriData['scheme'],
    userinfo: uriData['userinfo'],
    host: uriData['host'],
    port: uriData['port'],
    path: uriData['path'],
    query: uriData['query'],
    fragment: uriData['fragment'],
  };
  return uriObject;
}

/**
 * Stringify an [ERC-4361: Sign-In with Ethereum](https://eips.ethereum.org/EIPS/eip-4361) (siwe) object.
 *
 * @param {object} o an siwe message object (see {@link parseSiweMessage} )
 * @returns A stringified version of the object suitable as input to {@link parseSiweMessage}.
 *
 * For example, to validate an siwe object <br>*(ignore backslash, JSDoc can't handle closed bracket character without it)*:
 * ````
 * try{
 *  parseSiweMessage(siweObjectToString(siweObject));
 *  console.log('siweObject is valid');
 * \}catch(e){
 *  console.log('siweObject is not valid: ' + e.message);
 * \}
 * ````
 */
function siweObjectToString(o) {
  let str = '';
  if (o.scheme && o.scheme !== '') {
    str += `${o.scheme}://`;
  }
  if (o.domain && o.domain !== '') {
    str += o.domain;
  }
  str += ' wants you to sign in with your Ethereum account:\n';
  if (o.address && o.address !== '') {
    str += `${o.address}\n`;
  }
  str += '\n';
  if (o.statement !== undefined) {
    str += `${o.statement}\n`;
  }
  str += '\n';
  if (o.uri && o.uri !== '') {
    str += `URI: ${o.uri}\n`;
  }
  if (o['version'] && o['version'] !== '') {
    str += `Version: ${o['version']}\n`;
  }
  if (o['chainId'] && o['chainId'] !== '') {
    str += `Chain ID: ${o['chainId']}\n`;
  }
  if (o['nonce'] && o['nonce'] !== '') {
    str += `Nonce: ${o['nonce']}\n`;
  }
  if (o['issuedAt'] && o['issuedAt'] !== '') {
    str += `Issued At: ${o['issuedAt']}`;
  }
  if (o['expirationTime'] && o['expirationTime'] !== '') {
    str += `\nExpiration Time: ${o['expirationTime']}`;
  }
  if (o['notBefore'] && o['notBefore'] !== '') {
    str += `\nNot Before: ${o['notBefore']}`;
  }
  if (o['requestId'] !== undefined) {
    str += `\nRequest ID: ${o['requestId']}`;
  }
  if (o['resources']) {
    str += `\nResources:`;
    if (Array.isArray(o.resources)) {
      for (let i = 0; i < o.resources.length; i++) {
        str += `\n- ${o.resources[i]}`;
      }
    }
  }
  return str;
}
