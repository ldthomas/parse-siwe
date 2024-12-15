export { Trace };

import { utilities, identifiers } from './parser.js';

const Trace = function fntrace() {
  const id = identifiers;
  const utils = utilities;
  const thisFile = 'parser.js: Trace(): ';
  let chars = undefined;
  let rules = undefined;
  let udts = undefined;
  let out = '';
  let treeDepth = 0;
  const MAX_PHRASE = 100;
  const t = this;
  const indent = (n) => {
    let ret = '';
    let count = 0;
    if (n >= 0) {
      while (n--) {
        count += 1;
        if (count === 5) {
          ret += '|';
          count = 0;
        } else {
          ret += '.';
        }
      }
    }
    return ret;
  };
  t.init = (r, u, c) => {
    rules = r;
    udts = u;
    chars = c;
  };
  const opName = (op) => {
    let name;
    switch (op.type) {
      case id.ALT:
        name = 'ALT';
        break;
      case id.CAT:
        name = 'CAT';
        break;
      case id.REP:
        if (op.max === Infinity) {
          name = `REP(${op.min},inf)`;
        } else {
          name = `REP(${op.min},${op.max})`;
        }
        break;
      case id.RNM:
        name = `RNM(${rules[op.index].name})`;
        break;
      case id.TRG:
        name = `TRG(${op.min},${op.max})`;
        break;
      case id.TBS:
        if (op.string.length > 6) {
          name = `TBS(${utils.charsToString(op.string, 0, 3)}...)`;
        } else {
          name = `TBS(${utils.charsToString(op.string, 0, 6)})`;
        }
        break;
      case id.TLS:
        if (op.string.length > 6) {
          name = `TLS(${utils.charsToString(op.string, 0, 3)}...)`;
        } else {
          name = `TLS(${utils.charsToString(op.string, 0, 6)})`;
        }
        break;
      case id.UDT:
        name = `UDT(${udts[op.index].name})`;
        break;
      case id.AND:
        name = 'AND';
        break;
      case id.NOT:
        name = 'NOT';
        break;
      default:
        throw new Error(`${thisFile}Trace: opName: unrecognized opcode`);
    }
    return name;
  };
  t.down = (op, offset) => {
    const lead = indent(treeDepth);
    const len = Math.min(MAX_PHRASE, chars.length - offset);
    let phrase = utils.charsToString(chars, offset, len);
    if (len < chars.length - offset) {
      phrase += '...';
    }
    phrase = `${lead}|-|[${opName(op)}]${phrase}\n`;
    out += phrase;
    treeDepth += 1;
  };
  t.up = (op, state, offset, phraseLength) => {
    const thisFunc = `${thisFile}trace.up: `;
    treeDepth -= 1;
    const lead = indent(treeDepth);
    let len;
    let phrase;
    let st;
    switch (state) {
      case id.EMPTY:
        st = '|E|';
        phrase = `''`;
        break;
      case id.MATCH:
        st = '|M|';
        len = Math.min(MAX_PHRASE, phraseLength);
        if (len < phraseLength) {
          phrase = `'${utils.charsToString(chars, offset, len)}...'`;
        } else {
          phrase = `'${utils.charsToString(chars, offset, len)}'`;
        }
        break;
      case id.NOMATCH:
        st = '|N|';
        phrase = '';
        break;
      default:
        throw new Error(`${thisFunc} unrecognized state`);
    }
    phrase = `${lead}${st}[${opName(op)}]${phrase}\n`;
    out += phrase;
  };
  t.displayTrace = () => out;
};
