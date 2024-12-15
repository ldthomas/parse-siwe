// import { cwd } from 'node:process';
// console.log(`cwd: ${cwd()}`);
import { Parser } from '../src/parser.js';
import { default as Grammar } from '../src/grammar.js';

// test that the expansion of basic string definitions into
// TBS(Terminal Binary String) and TRG(Terminal Range) operators
// has been done correctly

const p = new Parser();
const g = new Grammar();
let result;
const unreserved = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~';
const genDelims = ':/?#[]@';
const subDelims = "!$&'()*+,;=";
const pchar = `${unreserved}${subDelims}:@%20`;
const pctEncoded = '%20%00%ff';
const reserved = `${genDelims}${subDelims}`;
describe.only('test of string exansions in character codes', () => {
  test('unreserved', () => {
    result = p.parse(g, 'statement', unreserved);
    expect(result.success).toBe(true);
  });
  test('sub-delims', () => {
    result = p.parse(g, 'statement', subDelims);
    expect(result.success).toBe(true);
  });
  test('gen-delims', () => {
    result = p.parse(g, 'statement', genDelims);
    expect(result.success).toBe(true);
  });
  test('pct-encoded', () => {
    result = p.parse(g, 'reg-name', pctEncoded);
    expect(result.success).toBe(true);
  });
  test('reserved', () => {
    result = p.parse(g, 'statement', reserved);
    expect(result.success).toBe(true);
  });
  test('unreserved', () => {
    result = p.parse(g, 'statement', unreserved);
    expect(result.success).toBe(true);
  });
  test('pchar', () => {
    result = p.parse(g, 'request-id', pchar);
    expect(result.success).toBe(true);
  });
});
