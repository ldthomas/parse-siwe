export { invalidMessages };

const invalidMessages = {
  'invalid scheme': {
    erc55: 'validate',
    error: 'invalid scheme',
    msg: `https$$://example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

Valid statement

URI: https://example.com/login
Version: 1
Chain ID: 123456789
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z`,
  },
  'invalid domain': {
    erc55: 'validate',
    error: 'invalid domain',
    msg: `example.com<80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

Valid statement

URI: https://example.com/login
Version: 1
Chain ID: 123456789
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z`,
  },
  'invalid address (not 42 characters)': {
    erc55: 'validate',
    error: 'invalid address',
    msg: `https://example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756C

Valid statement

URI: https://example.com/login
Version: 1
Chain ID: 123456789
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z`,
  },
  'invalid ERC-55 address': {
    erc55: 'validate',
    error: 'invalid ERC-55',
    msg: `https://example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756CC2

Valid statement

URI: https://example.com/login
Version: 1
Chain ID: 123456789
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z`,
  },
  'invalid statement: " characters not allowed': {
    erc55: '',
    error: 'invalid statement',
    msg: `example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

invalid "statement"

URI: https://example.com/login
Version: 1
Chain ID: 123456789
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z`,
  },
  'invalid URI': {
    erc55: '',
    error: 'invalid URI',
    msg: `example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2


URI: example.com/login
Version: 1
Chain ID: 123456789
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z`,
  },
  'invalid version': {
    erc55: '',
    error: 'invalid Version',
    msg: `example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2


URI: https://example.com/login
Version: 2
Chain ID: 123456789
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z`,
  },
  'invalid Chain ID': {
    erc55: '',
    error: 'invalid Chain ID',
    msg: `example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2


URI: https://example.com/login
Version: 1
Chain ID: 1FF
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z`,
  },
  'invalid Nonce': {
    erc55: '',
    error: 'invalid Nonce',
    msg: `example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2


URI: https://example.com/login
Version: 1
Chain ID: 2
Nonce: <32891756>
Issued At: 2021-09-30T16:25:24Z`,
  },
  'invalid Issued At': {
    erc55: '',
    error: 'invalid date time: Issued At',
    msg: `example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2


URI: https://example.com/login
Version: 1
Chain ID: 2
Nonce: 32891756
Issued At: 2021-09-30-16:25:24Z`,
  },
  'invalid Expiration Time': {
    erc55: '',
    error: 'invalid date time: Expiration Time',
    msg: `example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2


URI: https://example.com/login
Version: 1
Chain ID: 2
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Expiration Time: 2021-13-30T16:25:24Z`,
  },
  'invalid Not Before': {
    erc55: '',
    error: 'invalid date time: Not Before',
    msg: `example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2


URI: https://example.com/login
Version: 1
Chain ID: 2
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Expiration Time: 2021-09-30T16:25:24Z
Not Before: 2021-09-33T16:25:24Z`,
  },
  'invalid Request ID: bad pchar #': {
    erc55: '',
    error: 'invalid Request ID',
    msg: `example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2


URI: https://example.com/login
Version: 1
Chain ID: 2
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Request ID: anybut#`,
  },
  'invalid resource URI': {
    erc55: '',
    error: 'invalid resource URI',
    msg: `example.com:80 wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2


URI: https://example.com/login
Version: 1
Chain ID: 2
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Resources:
- example.com`,
  },
};
