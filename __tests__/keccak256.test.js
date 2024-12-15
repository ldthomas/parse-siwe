import { keccak256, isERC55 } from '../src/keccak256.js';

const msgs = [
  ['', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'],
  ['Hello world!', 'ecd0e108a98e192af1d2c25055f4e3bed784b5c877204e73219a5203251feaab'],
  ['keccak', 'df35a135a69c769066bbb4d17b2fa3ec922c028d4e4bf9d0402e6f7c12b31813'],
  ['keccak_256', 'd6633b225863f8623efe06af1b053554b203a03fa1a8bfd8a17da1cee7f14429'],
  [
    'd6633b225863f8623efe06af1b053554b203a03fa1a8bfd8a17da1cee7f14429',
    'a955cbb4b30c283b9845293f9cdea561a88f14d4e9e1f9730b28c2405971e079',
  ],
  ['71C7656EC7ab88b098defB751B7401B5f6d8976F', '7a49fed03e8f01b3b011def375a241ae94adcd94d6a6afdc421e3a7785857c12'],
  ['C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', '93e3e75c7d20551f7776b0eae478ef86a1b67dfb1cb78fa65abe9cb4339bff91'],
  ['40B38765696e3d5d8d9d834D8AaD4bB6e418E489', '3d89789ba3a12d843532c3eba1b6dac70b2232b5b69a58bd3f13520f9fbf64bc'],
  ['8315177aB297bA92A06054cE80a67Ed4DBd7ed3a', '820c02ca64785da89e5d9c8133fbee7a40e93a88a83ee3061a65de666f06611e'],
  // ['', ''],
];

const addresses = [
  ['good address from https://eips.ethereum.org/EIPS/eip-55', '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', true],
  ['good address from https://eips.ethereum.org/EIPS/eip-55', '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359', true],
  ['good address from https://eips.ethereum.org/EIPS/eip-55', '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB', true],
  ['good address from https://eips.ethereum.org/EIPS/eip-55', '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb', true],
  ['good address from https://eips.ethereum.org/EIPS/eip-55', '0x52908400098527886E0F7030069857D2E4169EE7', true],
  ['good address from https://eips.ethereum.org/EIPS/eip-55', '0x8617E340B3D01FA5F11F306F4090FD50E238070D', true],
  ['good address from https://eips.ethereum.org/EIPS/eip-55', '0xde709f2102306220921060314715629080e2fb77', true],
  ['randomly typed bad address', '0xffeeddccbbaa0a0b0c0d0e0f1a1b1c1d1e1f2a2b', false],
  ['good addresses with a single character miscopied', '0x5bAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', false],
  ['good addresses with a single character miscopied', '0xfB6916095ca1df60eB79Ce92cE3Ea74c37c5d359', false],
  ['good addresses with a single character miscopied', '0xdbF03B407c01E7cD3CBea99509d93f8DDDE8C6FB', false],
  ['good addresses with a single character miscopied', '0xD1220A0cf47c7B9Bc7A2E6BA89F429762e7b9aDb', false],
  ['good addresses with a single character miscopied', '0x52908400098527886E0F7030069857D2E4169EF7', false],
  ['good addresses with a single character miscopied', '0x8617E340B3D01FA5F11E306F4090FD50E238070D', false],
  ['bad address', '0xde709f2102306220921060314715629080c2fb77', false],
  ['not a string', [1, 2], false],
  ['invalid hex characters', '0xgh709f2102306220921060314715629080c2fb77', false],
  ['wrong length', '0xdede709f2102306220921060314715629080c2fb77', false],
];
describe('test keccak_256', () => {
  test.concurrent.each(msgs)('input string: %s', (msg, hash) => {
    expect(keccak256(msg)).toBe(hash);
  });
  test('undefined input', () => {
    expect(() => {
      keccak256();
    }).toThrow();
  });
  test('array input', () => {
    expect(() => {
      keccak256([1, 2]);
    }).toThrow();
  });
  test('Uint8Array input', () => {
    expect(() => {
      keccak256(new Uint8Array([1, 2]));
    }).toThrow();
  });
  test('non-ASCII string input', () => {
    expect(() => {
      keccak256('abc\xff');
    }).toThrow();
  });
});
describe('test ERC-55 address encoding', () => {
  test.concurrent.each(addresses)('%s: address: %s', (comment, address, value) => {
    expect(isERC55(address)).toBe(value);
  });
});
