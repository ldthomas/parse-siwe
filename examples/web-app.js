const siweMsg = `https://example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

Valid statement

URI: https://example.com/login
Version: 1
Chain ID: 123456789
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Expiration Time: 2021-06-01T16:59:59Z
Not Before: 2021-07-06T23:59:59Z
Request ID: requestIdentifier
Resources:
- https://anysite.com/anypage
- ftp://myftpsite.com`;
const siweObj = `{
  "scheme": "https",
  "domain": "example.com:80",
  "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
  "statement": "Valid statement",
  "uri": "https://example.com/login",
  "version": 1,
  "chainId": 123456789,
  "nonce": "32891756",
  "issuedAt": "2021-09-30T16:25:24Z",
  "expirationTime": "2021-06-01T16:59:59Z",
  "notBefore": "2021-07-06T23:59:59Z",
  "requestId": "requestIdentifier",
  "resources": [
    "https://anysite.com/anypage",
    "ftp://myftpsite.com"
  ]
}`;
const uriTest = 'uri://user:pass@example.com:123/one/two.three?q1=a1&q2=a2#body';
const keccakTest = 'Hello world!';
const iserc55Test = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const toerc55Test = '0xffeeddccbbaa0a0b0c0d0e0f1a1b1c1d1e1f2a2b';
function clearAll() {
  $('#button_parse').prop('disabled', true);
  $('#button_tostring').prop('disabled', true);
  $('#button_isuri').prop('disabled', true);
  $('#button_keccak256').prop('disabled', true);
  $('#button_iserc55').prop('disabled', true);
  $('#button_toerc55').prop('disabled', true);
  $('#input').val('');
  $('#erc55').val('');
  $('#value').html('');
}
const parseSetup = () => {
  clearAll();
  $('#button_parse').prop('disabled', false);
  $('#input').val(siweMsg);
  $('#erc55').val('validate');
};
const tostringSetup = () => {
  clearAll();
  $('#button_tostring').prop('disabled', false);
  $('#input').val(siweObj);
  $('#erc55').val('');
};
const isuriSetup = () => {
  clearAll();
  $('#button_isuri').prop('disabled', false);
  $('#input').val(uriTest);
  $('#erc55').val('');
};
const keccak256Setup = () => {
  clearAll();
  $('#button_keccak256').prop('disabled', false);
  $('#input').val(keccakTest);
  $('#erc55').val('');
};
const iserc55Setup = () => {
  clearAll();
  $('#button_iserc55').prop('disabled', false);
  $('#input').val(iserc55Test);
  $('#erc55').val('');
};
const toerc55Setup = () => {
  clearAll();
  $('#button_toerc55').prop('disabled', false);
  $('#input').val(toerc55Test);
  $('#erc55').val('');
};
const parseInput = () => {
  const inputString = $('#input').val();
  const erc55 = $('#erc55').val();
  try {
    const msgObj = _ps.parseSiweMessage(inputString, erc55);
    $('#value').html(JSON.stringify(msgObj, null, 2));
  } catch (e) {
    $('#value').html(`parsing error: ${e.message}`);
  }
};
const tostringInput = () => {
  const inputString = $('#input').val();
  try {
    const msg = _ps.siweObjectToString(JSON.parse(inputString));
    $('#value').html(msg);
  } catch (e) {
    $('#value').html(`processing error: ${e.message}`);
  }
};
const isuriInput = () => {
  const inputString = $('#input').val();
  try {
    const obj = _ps.isUri(inputString);
    if (!obj) {
      throw new Error('invalid URI input');
    }
    $('#value').html(JSON.stringify(obj, null, 2));
  } catch (e) {
    $('#value').html(`processing error: ${e.message}`);
  }
};
const keccakInput = () => {
  const inputString = $('#input').val();
  try {
    const hash = _ps.keccak256(inputString);
    $('#value').html(hash);
  } catch (e) {
    $('#value').html(`processing error: ${e.message}`);
  }
};
const iserc55Input = () => {
  const inputString = $('#input').val();
  try {
    let test = _ps.isERC55(inputString);
    test = test ? 'true' : 'false';
    $('#value').html(test);
  } catch (e) {
    $('#value').html(`processing error: ${e.message}`);
  }
};
const toerc55Input = () => {
  const inputString = $('#input').val();
  try {
    const hash = _ps.toERC55(inputString);
    $('#value').html(hash);
  } catch (e) {
    $('#value').html(`processing error: ${e.message}`);
  }
};
$(document).ready(() => {
  clearAll();
  $('#in_parse').click(parseSetup);
  $('#in_tostring').click(tostringSetup);
  $('#in_isuri').click(isuriSetup);
  $('#in_keccak256').click(keccak256Setup);
  $('#in_iserc55').click(iserc55Setup);
  $('#in_toerc55').click(toerc55Setup);
  $('#button_parse').click(parseInput);
  $('#button_tostring').click(tostringInput);
  $('#button_isuri').click(isuriInput);
  $('#button_keccak256').click(keccakInput);
  $('#button_iserc55').click(iserc55Input);
  $('#button_toerc55').click(toerc55Input);
});
