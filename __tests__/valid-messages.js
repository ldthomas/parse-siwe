export { validMessages };

const validMessages = {
  'missing resources': {
    erc55: 'validate',
    error: '',
    items: ['resources'],
    itemValues: [undefined],
    msg: {
      domain: 'service.org',
      address: '0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946',
      statement: 'I accept the ServiceOrg Terms of Service: https://service.org/tos',
      uri: 'https://sample.org',
      version: '1',
      chainId: 1,
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
      issuedAt: '2023-03-17T12:45:13.610Z',
      issuedAt: '2022-03-17T12:45:13.610Z',
      requestId: 'some_id',
    },
  },
  'empty resources': {
    msg: {
      domain: 'service.org',
      address: '0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946',
      uri: 'https://sample.org',
      version: '1',
      chainId: 1,
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
      resources: [],
    },
    items: ['resources'],
    itemValues: [[]],
    erc55: 'validate',
    error: '',
  },
  'multiple resources': {
    msg: {
      domain: 'service.org',
      address: '0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946',
      uri: 'https://sample.org',
      version: '1',
      chainId: 1,
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
      resources: ['https://example.com', 'https://example.net'],
    },
    items: ['resources'],
    itemValues: [['https://example.com', 'https://example.net']],
    erc55: 'validate',
    error: '',
  },
  'missing statement': {
    msg: {
      domain: 'service.org',
      address: '0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946',
      uri: 'https://sample.org',
      version: '1',
      chainId: 1,
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
    },
    items: ['statement'],
    itemValues: [undefined],
    erc55: 'validate',
    error: '',
  },
  'empty statement': {
    msg: {
      domain: 'service.org',
      address: '0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946',
      statement: '',
      uri: 'https://sample.org',
      version: '1',
      chainId: 1,
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
    },
    items: ['statement'],
    itemValues: [''],
    erc55: 'validate',
    error: '',
  },
  'full statement': {
    msg: {
      domain: 'service.org',
      address: '0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946',
      statement: 'the purpose of this login request is a test',
      uri: 'https://sample.org',
      version: '1',
      chainId: 1,
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
    },
    items: ['statement'],
    itemValues: ['the purpose of this login request is a test'],
    erc55: 'validate',
    error: '',
  },
  'missing request id': {
    msg: {
      domain: 'service.org',
      address: '0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946',
      uri: 'https://sample.org',
      version: '1',
      chainId: 1,
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
    },
    items: ['requestId'],
    itemValues: [undefined],
    erc55: 'validate',
    error: '',
  },
  'empty request id': {
    msg: {
      domain: 'service.org',
      address: '0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946',
      uri: 'https://sample.org',
      version: '1',
      chainId: 1,
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
      requestId: '',
    },
    items: ['requestId'],
    itemValues: [''],
    erc55: 'validate',
    error: '',
  },
  'full request id': {
    msg: {
      domain: 'service.org',
      address: '0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946',
      uri: 'https://sample.org',
      version: '1',
      chainId: 1,
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
      requestId: 'alpha%ff1234567890',
    },
    items: ['requestId'],
    itemValues: ['alpha%ff1234567890'],
    erc55: 'validate',
    error: '',
  },
  'missing scheme': {
    erc55: 'validate',
    error: '',
    items: ['scheme'],
    itemValues: [undefined],
    msg: {
      domain: 'service.org',
      address: '0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946',
      statement: 'I accept the ServiceOrg Terms of Service: https://service.org/tos',
      uri: 'https://sample.org',
      version: '1',
      chainId: '2',
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
      issuedAt: '2023-03-17T12:45:13.610Z',
      issuedAt: '2022-03-17T12:45:13.610Z',
      requestId: 'some_id',
    },
  },
  'version & chain-id as strings': {
    erc55: 'validate',
    error: '',
    items: ['version', 'chainId'],
    itemValues: [1, 2],
    msg: {
      domain: 'service.org',
      address: '0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946',
      statement: 'I accept the ServiceOrg Terms of Service: https://service.org/tos',
      uri: 'https://sample.org',
      version: '1',
      chainId: '2',
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
      issuedAt: '2023-03-17T12:45:13.610Z',
      issuedAt: '2022-03-17T12:45:13.610Z',
      requestId: 'some_id',
    },
  },
  'version & chain-id as numbers': {
    erc55: 'validate',
    error: '',
    items: ['version', 'chainId'],
    itemValues: [1, 2],
    msg: {
      domain: 'service.org',
      address: '0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946',
      statement: 'I accept the ServiceOrg Terms of Service: https://service.org/tos',
      uri: 'https://sample.org',
      version: 1,
      chainId: 2,
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
      issuedAt: '2023-03-17T12:45:13.610Z',
      issuedAt: '2022-03-17T12:45:13.610Z',
      requestId: 'some_id',
    },
  },
  'all optional elements missing': {
    msg: {
      domain: 'service.org',
      address: '0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946',
      uri: 'https://sample.org',
      version: '1',
      chainId: 1,
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
    },
    items: ['scheme', 'statement', 'expirationTime', 'notBefore', 'requestId', 'resources'],
    itemValues: [undefined, undefined, undefined, undefined, undefined, undefined],
    erc55: 'validate',
    error: '',
  },
  'convert address to ERC55 format': {
    msg: {
      domain: 'service.org',
      address: '0xe5a12547fe4e872d192e3ececb76f2ce1aea4946',
      statement: 'I accept the ServiceOrg Terms of Service: https://service.org/tos',
      uri: 'https://sample.org',
      version: '1',
      chainId: 1,
      nonce: '12341234',
      issuedAt: '2022-03-17T12:45:13.610Z',
      issuedAt: '2023-03-17T12:45:13.610Z',
      issuedAt: '2022-03-17T12:45:13.610Z',
      requestId: 'some_id',
    },
    items: ['address'],
    itemValues: ['0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946'],
    erc55: 'convert',
    error: '',
  },
};
