## parse-siwe - a "Sign in with Ethereum" Parser

[ERC-4361: Sign-In with Ethereum](https://eips.ethereum.org/EIPS/eip-4361)
establishes a standard for using an Ethereum account to sign into services that support the standard.
ERC-4361 defines a message format for this purpose and any application implementing
the standard will need to parse that message, validating each of the line items defined in it.
`parse-siwe` is such a parser. It is designed to be simple to use and simple to integrate into
either Node.js or web page applications.

Some highlights of its features:

- it is stand alone - it has no external dependencies
- well-tested
- URI validation - includes a complete and well-tested URI parser
- [ERC-55](https://eips.ethereum.org/EIPS/eip-55) options
  - validation of Ethereum address ERC-55 encoding
  - convert the Ethereum address to ERC-55 encoding
  - ignore ERC-55 encoding
- date time validation
- correct handling of `statement`, `request ID` and `resources`
  - these optional items can be empty as well as missing or present
- good error reporting (Well, pretty good. Usually, but not always, points out the offending message line.)
- can be used in Node.js or web page application

### Node.js Usage

```
import { parseSiweMessage } from 'parse-siwe';

const msg = `example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

Valid statement

URI: https://example.com/login
Version: 1
Chain ID: 2
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Request ID: someRequestId
Resources:
- ftp://myftpsite.com/
- https://example.com/mypage`;

try {
  const obj = parseSiweMessage(msg, 'validate');
  console.log('output message object');
  console.dir(obj);
} catch (e) {
  console.log(`parsing error: ${e.message}`);
}

```

`parse-siwe` exports the following functions:

```
parseSiweMessage()
siweObjectToString()
isUri()
keccak256()
isERC55()
toERC5()
```

[./examples/node-app.js](https://github.com/ldthomas/parse-siwe/blob/main/examples/node-app.js)
provides a more complete example of its usage.

### Web Page Usage

`src/parse-siwe-cat.js` and its minimized version, `src/parse-siwe-min.js`,
when scripted into a web page define the object `_ps` whose members are all of the
exported functions. It is implemented as a self-executing function so that
only the variable `_ps` is exposed to the global namespace.

```
_ps.parseSiweMessage()
_ps.siweObjectToString()
_ps.isUri()
_ps.keccak256()
_ps.isERC55()
_ps.toERC55()
_ps.noConflict()
```

[./examples/web.html](https://github.com/ldthomas/parse-siwe/blob/main/examples/web.html)
demonstrates all of these functions in a simple web page.

In the unlikely event that you need the variable `_ps` for some other purpose,
we follow the [jQuery.noConflict()](https://api.jquery.com/jQuery.noConflict/) convention.
This implementation may not be as sophisticated as `jQuery`, however, `noConflict()`
will remove `_ps` from the global namespace and return a reference to the `parse-siwe` object.
For example,

```
$(document).ready(() => {
  $$$ = _ps.noConflict();
  _ps = {};
  /*
   * From here on $$$ references the parse-siwe object and _ps can be
   * used for whatever value or object your application requires.
  */
});
```

## Documentation

The documentation is in the code as [JSDoc](https://jsdoc.app/) comments.
To generate the documentation use

```
npm run jsdoc
```

The documentation will be at `out/index.html`.
Or view it online [here](https://sabnf.com/docs/parse-siwe/index.html).

## License

[The MIT License](https://opensource.org/license/mit)
