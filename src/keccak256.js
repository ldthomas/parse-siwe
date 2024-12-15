/**
 * @file src/keccak256.js
 * @author https://github.com/cryptocoinjs/keccak contributors
 */
export { keccak256, toERC55, isERC55 };

/**
 * Converts an Ethereum address to [ERC-55: Mixed-case checksum address encoding](https://eips.ethereum.org/EIPS/eip-55).
 *
 * @param {string} address 40-byte hex string beginning with '0x'
 * @returns address in correct `ERC-55` encoding
 *
 * For example:
 * ````
 * '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed' = toERC55('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed');
 * ````
 */
function toERC55(address) {
  if (typeof address !== 'string' || address.length != 42) {
    throw new Error('toERC55: input must be hex string representing 20 bytes');
  }
  const test = address.slice(2).toLowerCase();
  const hash = keccak256(test);
  let ret = '0x';
  let c;
  for (let i = 0; i < test.length; i++) {
    c = test.charCodeAt(i);
    if ((c >= 48 && c <= 57) || (c >= 97 && c <= 104)) {
      if (parseInt(hash[i], 16) >= 8) {
        ret += test[i].toUpperCase();
      } else {
        ret += test[i];
      }
    } else {
      throw new Error(`toERC55: input address is not hex: ${address}`);
    }
  }
  return ret;
}

/**
 * Checks an Ethereum address for [ERC-55: Mixed-case checksum address encoding](https://eips.ethereum.org/EIPS/eip-55).
 *
 * @param {string} Address 40-byte hex string beginning with '0x'. e.g.<br>
 * '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2'
 * @returns true if address is in correct `ERC-55` encoding,
 * false otherwise
 */
function isERC55(address) {
  let erc55;
  try {
    erc55 = toERC55(address);
    return address === erc55;
  } catch (e) {
    return false;
  }
}

const P1600_ROUND_CONSTANTS = [
  1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649, 0, 2147516545, 2147483648, 32777,
  2147483648, 138, 0, 136, 0, 2147516425, 0, 2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771,
  2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648, 2147516545, 2147483648, 32896,
  2147483648, 2147483649, 0, 2147516424, 2147483648,
];

function p1600(s) {
  for (let round = 0; round < 24; ++round) {
    // theta
    const lo0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40];
    const hi0 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41];
    const lo1 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42];
    const hi1 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43];
    const lo2 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44];
    const hi2 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45];
    const lo3 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46];
    const hi3 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47];
    const lo4 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48];
    const hi4 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49];

    let lo = lo4 ^ ((lo1 << 1) | (hi1 >>> 31));
    let hi = hi4 ^ ((hi1 << 1) | (lo1 >>> 31));
    const t1slo0 = s[0] ^ lo;
    const t1shi0 = s[1] ^ hi;
    const t1slo5 = s[10] ^ lo;
    const t1shi5 = s[11] ^ hi;
    const t1slo10 = s[20] ^ lo;
    const t1shi10 = s[21] ^ hi;
    const t1slo15 = s[30] ^ lo;
    const t1shi15 = s[31] ^ hi;
    const t1slo20 = s[40] ^ lo;
    const t1shi20 = s[41] ^ hi;
    lo = lo0 ^ ((lo2 << 1) | (hi2 >>> 31));
    hi = hi0 ^ ((hi2 << 1) | (lo2 >>> 31));
    const t1slo1 = s[2] ^ lo;
    const t1shi1 = s[3] ^ hi;
    const t1slo6 = s[12] ^ lo;
    const t1shi6 = s[13] ^ hi;
    const t1slo11 = s[22] ^ lo;
    const t1shi11 = s[23] ^ hi;
    const t1slo16 = s[32] ^ lo;
    const t1shi16 = s[33] ^ hi;
    const t1slo21 = s[42] ^ lo;
    const t1shi21 = s[43] ^ hi;
    lo = lo1 ^ ((lo3 << 1) | (hi3 >>> 31));
    hi = hi1 ^ ((hi3 << 1) | (lo3 >>> 31));
    const t1slo2 = s[4] ^ lo;
    const t1shi2 = s[5] ^ hi;
    const t1slo7 = s[14] ^ lo;
    const t1shi7 = s[15] ^ hi;
    const t1slo12 = s[24] ^ lo;
    const t1shi12 = s[25] ^ hi;
    const t1slo17 = s[34] ^ lo;
    const t1shi17 = s[35] ^ hi;
    const t1slo22 = s[44] ^ lo;
    const t1shi22 = s[45] ^ hi;
    lo = lo2 ^ ((lo4 << 1) | (hi4 >>> 31));
    hi = hi2 ^ ((hi4 << 1) | (lo4 >>> 31));
    const t1slo3 = s[6] ^ lo;
    const t1shi3 = s[7] ^ hi;
    const t1slo8 = s[16] ^ lo;
    const t1shi8 = s[17] ^ hi;
    const t1slo13 = s[26] ^ lo;
    const t1shi13 = s[27] ^ hi;
    const t1slo18 = s[36] ^ lo;
    const t1shi18 = s[37] ^ hi;
    const t1slo23 = s[46] ^ lo;
    const t1shi23 = s[47] ^ hi;
    lo = lo3 ^ ((lo0 << 1) | (hi0 >>> 31));
    hi = hi3 ^ ((hi0 << 1) | (lo0 >>> 31));
    const t1slo4 = s[8] ^ lo;
    const t1shi4 = s[9] ^ hi;
    const t1slo9 = s[18] ^ lo;
    const t1shi9 = s[19] ^ hi;
    const t1slo14 = s[28] ^ lo;
    const t1shi14 = s[29] ^ hi;
    const t1slo19 = s[38] ^ lo;
    const t1shi19 = s[39] ^ hi;
    const t1slo24 = s[48] ^ lo;
    const t1shi24 = s[49] ^ hi;

    // rho & pi
    const t2slo0 = t1slo0;
    const t2shi0 = t1shi0;
    const t2slo16 = (t1shi5 << 4) | (t1slo5 >>> 28);
    const t2shi16 = (t1slo5 << 4) | (t1shi5 >>> 28);
    const t2slo7 = (t1slo10 << 3) | (t1shi10 >>> 29);
    const t2shi7 = (t1shi10 << 3) | (t1slo10 >>> 29);
    const t2slo23 = (t1shi15 << 9) | (t1slo15 >>> 23);
    const t2shi23 = (t1slo15 << 9) | (t1shi15 >>> 23);
    const t2slo14 = (t1slo20 << 18) | (t1shi20 >>> 14);
    const t2shi14 = (t1shi20 << 18) | (t1slo20 >>> 14);
    const t2slo10 = (t1slo1 << 1) | (t1shi1 >>> 31);
    const t2shi10 = (t1shi1 << 1) | (t1slo1 >>> 31);
    const t2slo1 = (t1shi6 << 12) | (t1slo6 >>> 20);
    const t2shi1 = (t1slo6 << 12) | (t1shi6 >>> 20);
    const t2slo17 = (t1slo11 << 10) | (t1shi11 >>> 22);
    const t2shi17 = (t1shi11 << 10) | (t1slo11 >>> 22);
    const t2slo8 = (t1shi16 << 13) | (t1slo16 >>> 19);
    const t2shi8 = (t1slo16 << 13) | (t1shi16 >>> 19);
    const t2slo24 = (t1slo21 << 2) | (t1shi21 >>> 30);
    const t2shi24 = (t1shi21 << 2) | (t1slo21 >>> 30);
    const t2slo20 = (t1shi2 << 30) | (t1slo2 >>> 2);
    const t2shi20 = (t1slo2 << 30) | (t1shi2 >>> 2);
    const t2slo11 = (t1slo7 << 6) | (t1shi7 >>> 26);
    const t2shi11 = (t1shi7 << 6) | (t1slo7 >>> 26);
    const t2slo2 = (t1shi12 << 11) | (t1slo12 >>> 21);
    const t2shi2 = (t1slo12 << 11) | (t1shi12 >>> 21);
    const t2slo18 = (t1slo17 << 15) | (t1shi17 >>> 17);
    const t2shi18 = (t1shi17 << 15) | (t1slo17 >>> 17);
    const t2slo9 = (t1shi22 << 29) | (t1slo22 >>> 3);
    const t2shi9 = (t1slo22 << 29) | (t1shi22 >>> 3);
    const t2slo5 = (t1slo3 << 28) | (t1shi3 >>> 4);
    const t2shi5 = (t1shi3 << 28) | (t1slo3 >>> 4);
    const t2slo21 = (t1shi8 << 23) | (t1slo8 >>> 9);
    const t2shi21 = (t1slo8 << 23) | (t1shi8 >>> 9);
    const t2slo12 = (t1slo13 << 25) | (t1shi13 >>> 7);
    const t2shi12 = (t1shi13 << 25) | (t1slo13 >>> 7);
    const t2slo3 = (t1slo18 << 21) | (t1shi18 >>> 11);
    const t2shi3 = (t1shi18 << 21) | (t1slo18 >>> 11);
    const t2slo19 = (t1shi23 << 24) | (t1slo23 >>> 8);
    const t2shi19 = (t1slo23 << 24) | (t1shi23 >>> 8);
    const t2slo15 = (t1slo4 << 27) | (t1shi4 >>> 5);
    const t2shi15 = (t1shi4 << 27) | (t1slo4 >>> 5);
    const t2slo6 = (t1slo9 << 20) | (t1shi9 >>> 12);
    const t2shi6 = (t1shi9 << 20) | (t1slo9 >>> 12);
    const t2slo22 = (t1shi14 << 7) | (t1slo14 >>> 25);
    const t2shi22 = (t1slo14 << 7) | (t1shi14 >>> 25);
    const t2slo13 = (t1slo19 << 8) | (t1shi19 >>> 24);
    const t2shi13 = (t1shi19 << 8) | (t1slo19 >>> 24);
    const t2slo4 = (t1slo24 << 14) | (t1shi24 >>> 18);
    const t2shi4 = (t1shi24 << 14) | (t1slo24 >>> 18);

    // chi
    s[0] = t2slo0 ^ (~t2slo1 & t2slo2);
    s[1] = t2shi0 ^ (~t2shi1 & t2shi2);
    s[10] = t2slo5 ^ (~t2slo6 & t2slo7);
    s[11] = t2shi5 ^ (~t2shi6 & t2shi7);
    s[20] = t2slo10 ^ (~t2slo11 & t2slo12);
    s[21] = t2shi10 ^ (~t2shi11 & t2shi12);
    s[30] = t2slo15 ^ (~t2slo16 & t2slo17);
    s[31] = t2shi15 ^ (~t2shi16 & t2shi17);
    s[40] = t2slo20 ^ (~t2slo21 & t2slo22);
    s[41] = t2shi20 ^ (~t2shi21 & t2shi22);
    s[2] = t2slo1 ^ (~t2slo2 & t2slo3);
    s[3] = t2shi1 ^ (~t2shi2 & t2shi3);
    s[12] = t2slo6 ^ (~t2slo7 & t2slo8);
    s[13] = t2shi6 ^ (~t2shi7 & t2shi8);
    s[22] = t2slo11 ^ (~t2slo12 & t2slo13);
    s[23] = t2shi11 ^ (~t2shi12 & t2shi13);
    s[32] = t2slo16 ^ (~t2slo17 & t2slo18);
    s[33] = t2shi16 ^ (~t2shi17 & t2shi18);
    s[42] = t2slo21 ^ (~t2slo22 & t2slo23);
    s[43] = t2shi21 ^ (~t2shi22 & t2shi23);
    s[4] = t2slo2 ^ (~t2slo3 & t2slo4);
    s[5] = t2shi2 ^ (~t2shi3 & t2shi4);
    s[14] = t2slo7 ^ (~t2slo8 & t2slo9);
    s[15] = t2shi7 ^ (~t2shi8 & t2shi9);
    s[24] = t2slo12 ^ (~t2slo13 & t2slo14);
    s[25] = t2shi12 ^ (~t2shi13 & t2shi14);
    s[34] = t2slo17 ^ (~t2slo18 & t2slo19);
    s[35] = t2shi17 ^ (~t2shi18 & t2shi19);
    s[44] = t2slo22 ^ (~t2slo23 & t2slo24);
    s[45] = t2shi22 ^ (~t2shi23 & t2shi24);
    s[6] = t2slo3 ^ (~t2slo4 & t2slo0);
    s[7] = t2shi3 ^ (~t2shi4 & t2shi0);
    s[16] = t2slo8 ^ (~t2slo9 & t2slo5);
    s[17] = t2shi8 ^ (~t2shi9 & t2shi5);
    s[26] = t2slo13 ^ (~t2slo14 & t2slo10);
    s[27] = t2shi13 ^ (~t2shi14 & t2shi10);
    s[36] = t2slo18 ^ (~t2slo19 & t2slo15);
    s[37] = t2shi18 ^ (~t2shi19 & t2shi15);
    s[46] = t2slo23 ^ (~t2slo24 & t2slo20);
    s[47] = t2shi23 ^ (~t2shi24 & t2shi20);
    s[8] = t2slo4 ^ (~t2slo0 & t2slo1);
    s[9] = t2shi4 ^ (~t2shi0 & t2shi1);
    s[18] = t2slo9 ^ (~t2slo5 & t2slo6);
    s[19] = t2shi9 ^ (~t2shi5 & t2shi6);
    s[28] = t2slo14 ^ (~t2slo10 & t2slo11);
    s[29] = t2shi14 ^ (~t2shi10 & t2shi11);
    s[38] = t2slo19 ^ (~t2slo15 & t2slo16);
    s[39] = t2shi19 ^ (~t2shi15 & t2shi16);
    s[48] = t2slo24 ^ (~t2slo20 & t2slo21);
    s[49] = t2shi24 ^ (~t2shi20 & t2shi21);

    // iota
    s[0] ^= P1600_ROUND_CONSTANTS[round * 2];
    s[1] ^= P1600_ROUND_CONSTANTS[round * 2 + 1];
  }
}

function KeccakState() {
  // much faster than `new Array(50)`
  this.state = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

  this.blockSize = null;
  this.count = 0;
  this.squeezing = false;
}

KeccakState.prototype.initialize = function (rate, capacity) {
  for (let i = 0; i < 50; ++i) this.state[i] = 0;
  this.blockSize = rate / 8;
  this.count = 0;
  this.squeezing = false;
};

KeccakState.prototype.absorb = function (data) {
  for (let i = 0; i < data.length; ++i) {
    this.state[~~(this.count / 4)] ^= data[i] << (8 * (this.count % 4));
    this.count += 1;
    if (this.count === this.blockSize) {
      p1600(this.state);
      this.count = 0;
    }
  }
};

KeccakState.prototype.absorbLastFewBits = function (bits) {
  this.state[~~(this.count / 4)] ^= bits << (8 * (this.count % 4));
  if ((bits & 0x80) !== 0 && this.count === this.blockSize - 1) p1600(this.state);
  this.state[~~((this.blockSize - 1) / 4)] ^= 0x80 << (8 * ((this.blockSize - 1) % 4));
  p1600(this.state);
  this.count = 0;
  this.squeezing = true;
};

KeccakState.prototype.squeeze = function (length) {
  if (!this.squeezing) this.absorbLastFewBits(0x01);

  const output = new Uint8Array(length);
  for (let i = 0; i < length; ++i) {
    output[i] = (this.state[~~(this.count / 4)] >>> (8 * (this.count % 4))) & 0xff;
    this.count += 1;
    if (this.count === this.blockSize) {
      p1600(this.state);
      this.count = 0;
    }
  }

  return output;
};

KeccakState.prototype.copy = function (dest) {
  for (let i = 0; i < 50; ++i) dest.state[i] = this.state[i];
  dest.blockSize = this.blockSize;
  dest.count = this.count;
  dest.squeezing = this.squeezing;
};

function bytestohex(byteArray) {
  let hexString = '';
  for (let i = 0; i < byteArray.length; i++) {
    let hex = byteArray[i].toString(16);
    if (hex.length === 1) {
      hexString += '0';
    }
    hexString += hex;
  }
  return hexString;
}

/**
 * 
 * A keccak-256 hash function specialized for
 * ASCII-only string input (character codes 0 - 127). It is a modification of the general work
 * [https://github.com/cryptocoinjs/keccak](https://github.com/cryptocoinjs/keccak).
 * 
 * <i>CAVEAT: This function should never be used for secure cryptography purposes.
 * It is used here merely as a means of getting the correct hash for the [ERC-55](https://eips.ethereum.org/EIPS/eip-55)
 * Ethereum address checksum. It is assumed that security is not an issue for this use.</i>
* <br><br>The license for the original work is reproduced here.
 * ````
 The MIT License (MIT)

Copyright (c) 2016-2019 https://github.com/cryptocoinjs/keccak contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
* ````
 *
 * @param {string} msg must be a string of ASCII-only characters (character codes 0 - 127).
 * Will throw exception with any other type of input.
 * @returns The keccak-256 hash or digest of the input string. e.g.
````
keccak256('')             => 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
keccak256('Hello world!') => 'ecd0e108a98e192af1d2c25055f4e3bed784b5c877204e73219a5203251feaab'
````
 */
function keccak256(msg) {
  if (typeof msg !== 'string') {
    throw new Error(`keccak256: input must be string of ASCII-only characters`);
  }
  const data = new Uint8Array([...msg].map((cp) => cp.codePointAt(0)));
  for (let i = 0; i < data.length; i++) {
    if (data[i] > 127) {
      throw new Error(
        `keccak256: input must be string of ASCII-only characters: found character code ${data[i]} at offset ${i}`
      );
    }
  }
  const rate = 1088;
  const capacity = 512;
  const hashBitLength = 256;
  const state = new KeccakState();
  state.initialize(rate, capacity);
  state.absorb(data);
  return bytestohex(state.squeeze(hashBitLength / 8));
}
