const msg = `https://example.com:80 wants you to sign in with your Ethereum account:
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

const parseMsg = () => {
  console.log('parseMsg called');
  // get the input string (the number to parse) from the web page
  const inputString = $('#string').val();
  const erc55 = $('#erc55').val();

  // parse the input string
  try {
    const msgObj = parseSiweMessage(inputString, erc55);
    const objStr = JSON.stringify(msgObj, null, 2);
    // display the parsed object value
    $('#value').html(objStr);
  } catch (e) {
    // display the exception error
    $('#value').html(`parsing error: ${e.message}`);
  }
};
$(document).ready(() => {
  console.log('document ready called');
  $('#parse').click(parseMsg);
  $('#string').val(msg);
  $('#erc55').val('validate');
});
