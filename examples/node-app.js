import { parseSiweMessage, siweObjectToString, isUri } from '../src/parse-siwe.js';
import { isERC55, toERC55, keccak256 } from '../src/keccak256.js';

const msg = `https://example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

Valid statement

URI: https://example.com/login
Version: 1
Chain ID: 123456789
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Expiration Time: 2021-06-01T16:59:59Z
Request ID: 
Resources:
- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/
- https://example.com/my-web2-claim.json`;

const uri = 'uri://user:pass@example.com:123/one/two.three?q1=a1&q2=a2#body';
const badErc55 = '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed';
const goodErc55 = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const empty256 = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
try {
  console.log();
  console.log('parseSiweMessage() example');
  console.log('siwe message:\n');
  console.log(msg);
  console.log();
  console.log('parseSiweMessage(): the parsed message object');
  console.log();
  const obj = parseSiweMessage(msg);
  console.dir(obj);
  console.log();
  console.log('siweObjectToString(): convert the message object to a string');
  console.log();
  console.log(siweObjectToString(obj));
  console.log();
  console.log(`validate a URI: ${uri}`);
  const uriObj = isUri(uri);
  console.dir(uriObj);
  console.log();
  console.log(`keccak256(""): ${keccak256('')}`);
  console.log();
  console.log('ERC-55 tests');
  console.log(`${badErc55} is ERC-55: ${isERC55(badErc55)}`);
  console.log(`${goodErc55} is ERC-55: ${isERC55(goodErc55)}`);
  console.log(`${badErc55} to ERC-55: ${toERC55(badErc55)}`);
} catch (e) {
  console.log();
  console.log(`test error: ${e.message}`);
  console.log();
}
