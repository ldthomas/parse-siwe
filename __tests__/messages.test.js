import { parseSiweMessage, siweObjectToString } from '../src/parse-siwe.js';
import { validMessages } from './valid-messages.js';
import { invalidMessages } from './invalid-messages.js';

let re;
describe(`valid siwe message tests`, () => {
  test.concurrent.each(Object.entries(validMessages))('%s', (n, o) => {
    let msgObj = {};
    let erc55 = '';
    if (o.erc55 && typeof o.erc55 === 'string') {
      erc55 = o.erc55;
    }
    const message = siweObjectToString(o.msg);
    try {
      msgObj = parseSiweMessage(message, erc55);
      for (let i = 0; i < o.items.length; i++) {
        expect(msgObj[o.items[i]]).toEqual(o.itemValues[i]);
      }
    } catch (e) {
      console.log(message);
      for (let i = 0; i < o.items.length; i++) {
        console.log(`o.items: ${o.items[i]}: msgObj[o.items]: ${msgObj[o.items[i]]}`);
        console.log(`o.itemValues: ${o.itemValues[i]}`);
      }
      expect(true).toBe(false);
    }
  });
});
describe(`invalid siwe message tests`, () => {
  test.concurrent.each(Object.entries(invalidMessages))('%s', (n, o) => {
    let msgObj = {};
    let erc55 = '';
    if (o.erc55 && typeof o.erc55 === 'string') {
      erc55 = o.erc55;
    }
    try {
      msgObj = parseSiweMessage(o.msg, erc55);
      console.log(o.msg);
      expect(true).toBe(false);
    } catch (e) {
      // console.log(`catch error: ${e.message}`);
      // console.log(`expected error: ${o.error}`);
      re = new RegExp(o.error);
      expect(re.test(e.message)).toBe(true);
    }
  });
});
