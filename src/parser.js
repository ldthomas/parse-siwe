export { Parser, utilities, identifiers };

/*
 * This is the [apg-lite](https://github.com/ldthomas/apg-lite) parser.
 * Included here is only the `Parser` class and it's accompanying `identities` and `utilities`.
 * See [apg-lite](https://github.com/ldthomas/apg-lite) for details and detailed examples of its use.
 * The license for this code is reproduced here:
 * ````
 *   copyright: Copyright (c) 2023 Lowell D. Thomas, all rights reserved
 *     license: BSD-2-Clause (https://opensource.org/licenses/BSD-2-Clause)
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice, this
 *       list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 *    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *    OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ````
 */
const Parser = function fnparser() {
  const id = identifiers;
  const utils = utilities;
  const p = this;
  const thisFileName = 'parser.js: Parser(): ';
  const systemData = function systemData() {
    this.state = id.ACTIVE;
    this.phraseLength = 0;
    this.refresh = () => {
      this.state = id.ACTIVE;
      this.phraseLength = 0;
    };
  };
  p.ast = undefined;
  p.stats = undefined;
  p.trace = undefined;
  p.callbacks = [];
  let lookAhead = 0;
  let treeDepth = 0;
  let maxTreeDepth = 0;
  let nodeHits = 0;
  let maxMatched = 0;
  let rules = undefined;
  let udts = undefined;
  let opcodes = undefined;
  let chars = undefined;
  let sysData = new systemData();
  let ruleCallbacks = undefined;
  let udtCallbacks = undefined;
  let userData = undefined;
  const clear = () => {
    lookAhead = 0;
    treeDepth = 0;
    maxTreeDepth = 0;
    nodeHits = 0;
    maxMatched = 0;
    rules = undefined;
    udts = undefined;
    opcodes = undefined;
    chars = undefined;
    sysData.refresh();
    ruleCallbacks = undefined;
    udtCallbacks = undefined;
    userData = undefined;
  };

  const initializeCallbacks = () => {
    const functionName = `${thisFileName}initializeCallbacks(): `;
    let i;
    ruleCallbacks = [];
    udtCallbacks = [];
    for (i = 0; i < rules.length; i += 1) {
      ruleCallbacks[i] = undefined;
    }
    for (i = 0; i < udts.length; i += 1) {
      udtCallbacks[i] = undefined;
    }
    let func;
    const list = [];
    for (i = 0; i < rules.length; i += 1) {
      list.push(rules[i].lower);
    }
    for (i = 0; i < udts.length; i += 1) {
      list.push(udts[i].lower);
    }
    for (const index in p.callbacks) {
      if (p.callbacks.hasOwnProperty(index)) {
        i = list.indexOf(index.toLowerCase());
        if (i < 0) {
          throw new Error(`${functionName}syntax callback '${index}' not a rule or udt name`);
        }
        func = p.callbacks[index] ? p.callbacks[index] : undefined;
        if (typeof func === 'function' || func === undefined) {
          if (i < rules.length) {
            ruleCallbacks[i] = func;
          } else {
            udtCallbacks[i - rules.length] = func;
          }
        } else {
          throw new Error(`${functionName}syntax callback[${index}] must be function reference or falsy)`);
        }
      }
    }
  };

  p.parse = (grammar, startName, inputString, callbackData) => {
    const functionName = `${thisFileName}parse(): `;
    clear();
    chars = utils.stringToChars(inputString);
    rules = grammar.rules;
    udts = grammar.udts;
    const lower = startName.toLowerCase();
    let startIndex = undefined;
    for (const i in rules) {
      if (rules.hasOwnProperty(i)) {
        if (lower === rules[i].lower) {
          startIndex = rules[i].index;
          break;
        }
      }
    }
    if (startIndex === undefined) {
      throw new Error(`${functionName}start rule name '${startRule}' not recognized`);
    }
    initializeCallbacks();
    if (p.trace) {
      p.trace.init(rules, udts, chars);
    }
    if (p.stats) {
      p.stats.init(rules, udts);
    }
    if (p.ast) {
      p.ast.init(rules, udts, chars);
    }
    userData = callbackData;
    /* create a dummy opcode for the start rule */
    opcodes = [
      {
        type: id.RNM,
        index: startIndex,
      },
    ];
    /* execute the start rule */
    opExecute(0, 0);
    opcodes = undefined;
    /* test and return the sysData */
    let success = false;
    switch (sysData.state) {
      case id.ACTIVE:
        throw new Error(`${functionName}final state should never be 'ACTIVE'`);
      case id.NOMATCH:
        success = false;
        break;
      case id.EMPTY:
      case id.MATCH:
        if (sysData.phraseLength === chars.length) {
          success = true;
        } else {
          success = false;
        }
        break;
      default:
        throw new Error('unrecognized state');
    }
    return {
      success,
      state: sysData.state,
      stateName: id.idName(sysData.state),
      length: chars.length,
      matched: sysData.phraseLength,
      maxMatched,
      maxTreeDepth,
      nodeHits,
    };
  };
  // The `ALT` operator.<br>
  // Executes its child nodes, from left to right, until it finds a match.
  // Fails if *all* of its child nodes fail.
  const opALT = (opIndex, phraseIndex) => {
    const op = opcodes[opIndex];
    for (let i = 0; i < op.children.length; i += 1) {
      opExecute(op.children[i], phraseIndex);
      if (sysData.state !== id.NOMATCH) {
        break;
      }
    }
  };
  // The `CAT` operator.<br>
  // Executes all of its child nodes, from left to right,
  // concatenating the matched phrases.
  // Fails if *any* child nodes fail.
  const opCAT = (opIndex, phraseIndex) => {
    let success;
    let astLength;
    let catCharIndex;
    let catPhrase;
    const op = opcodes[opIndex];
    if (p.ast) {
      astLength = p.ast.getLength();
    }
    success = true;
    catCharIndex = phraseIndex;
    catPhrase = 0;
    for (let i = 0; i < op.children.length; i += 1) {
      opExecute(op.children[i], catCharIndex);
      if (sysData.state === id.NOMATCH) {
        success = false;
        break;
      } else {
        catCharIndex += sysData.phraseLength;
        catPhrase += sysData.phraseLength;
      }
    }
    if (success) {
      sysData.state = catPhrase === 0 ? id.EMPTY : id.MATCH;
      sysData.phraseLength = catPhrase;
    } else {
      sysData.state = id.NOMATCH;
      sysData.phraseLength = 0;
      if (p.ast) {
        p.ast.setLength(astLength);
      }
    }
  };
  // The `REP` operator.<br>
  // Repeatedly executes its single child node,
  // concatenating each of the matched phrases found.
  // The number of repetitions executed and its final sysData depends
  // on its `min` & `max` repetition values.
  const opREP = (opIndex, phraseIndex) => {
    let astLength;
    let repCharIndex;
    let repPhrase;
    let repCount;
    const op = opcodes[opIndex];
    if (op.max === 0) {
      // this is an empty-string acceptor
      // deprecated: use the TLS empty string operator, "", instead
      sysData.state = id.EMPTY;
      sysData.phraseLength = 0;
      return;
    }
    repCharIndex = phraseIndex;
    repPhrase = 0;
    repCount = 0;
    if (p.ast) {
      astLength = p.ast.getLength();
    }
    while (1) {
      if (repCharIndex >= chars.length) {
        /* exit on end of input string */
        break;
      }
      opExecute(opIndex + 1, repCharIndex);
      if (sysData.state === id.NOMATCH) {
        /* always end if the child node fails */
        break;
      }
      if (sysData.state === id.EMPTY) {
        /* REP always succeeds when the child node returns an empty phrase */
        /* this may not seem obvious, but that's the way it works out */
        break;
      }
      repCount += 1;
      repPhrase += sysData.phraseLength;
      repCharIndex += sysData.phraseLength;
      if (repCount === op.max) {
        /* end on maxed out reps */
        break;
      }
    }
    /* evaluate the match count according to the min, max values */
    if (sysData.state === id.EMPTY) {
      sysData.state = repPhrase === 0 ? id.EMPTY : id.MATCH;
      sysData.phraseLength = repPhrase;
    } else if (repCount >= op.min) {
      sysData.state = repPhrase === 0 ? id.EMPTY : id.MATCH;
      sysData.phraseLength = repPhrase;
    } else {
      sysData.state = id.NOMATCH;
      sysData.phraseLength = 0;
      if (p.ast) {
        p.ast.setLength(astLength);
      }
    }
  };
  // Validate the callback function's returned sysData values.
  // It's the user's responsibility to get them right
  // but `RNM` fails if not.
  const validateRnmCallbackResult = (rule, sysData, charsLeft, down) => {
    if (sysData.phraseLength > charsLeft) {
      let str = `${thisFileName}opRNM(${rule.name}): callback function error: `;
      str += `sysData.phraseLength: ${sysData.phraseLength}`;
      str += ` must be <= remaining chars: ${charsLeft}`;
      throw new Error(str);
    }
    switch (sysData.state) {
      case id.ACTIVE:
        if (!down) {
          throw new Error(
            `${thisFileName}opRNM(${rule.name}): callback function return error. ACTIVE state not allowed.`
          );
        }
        break;
      case id.EMPTY:
        sysData.phraseLength = 0;
        break;
      case id.MATCH:
        if (sysData.phraseLength === 0) {
          sysData.state = id.EMPTY;
        }
        break;
      case id.NOMATCH:
        sysData.phraseLength = 0;
        break;
      default:
        throw new Error(
          `${thisFileName}opRNM(${rule.name}): callback function return error. Unrecognized return state: ${sysData.state}`
        );
    }
  };
  // The `RNM` operator.<br>
  // This operator will acts as a root node for a parse tree branch below and
  // returns the matched phrase to its parent.
  // However, its larger responsibility is handling user-defined callback functions and `AST` nodes.
  // Note that the `AST` is a separate object, but `RNM` calls its functions to create its nodes.
  const opRNM = (opIndex, phraseIndex) => {
    let astLength;
    let astDefined;
    let savedOpcodes;
    const op = opcodes[opIndex];
    const rule = rules[op.index];
    const callback = ruleCallbacks[rule.index];
    /* ignore AST in look ahead (AND or NOT operator above) */
    if (!lookAhead) {
      astDefined = p.ast && p.ast.ruleDefined(op.index);
      if (astDefined) {
        astLength = p.ast.getLength();
        p.ast.down(op.index, rules[op.index].name);
      }
    }
    if (callback) {
      /* call user's callback going down the parse tree*/
      const charsLeft = chars.length - phraseIndex;
      callback(sysData, chars, phraseIndex, userData);
      validateRnmCallbackResult(rule, sysData, charsLeft, true);
      if (sysData.state === id.ACTIVE) {
        savedOpcodes = opcodes;
        opcodes = rule.opcodes;
        opExecute(0, phraseIndex);
        opcodes = savedOpcodes;
        /* call user's callback going up the parse tree*/
        callback(sysData, chars, phraseIndex, userData);
        validateRnmCallbackResult(rule, sysData, charsLeft, false);
      } /* implied else clause: just accept the callback sysData - RNM acting as UDT */
    } else {
      /* no callback - just execute the rule */
      savedOpcodes = opcodes;
      opcodes = rule.opcodes;
      opExecute(0, phraseIndex, sysData);
      opcodes = savedOpcodes;
    }
    if (!lookAhead) {
      /* end AST */
      if (astDefined) {
        if (sysData.state === id.NOMATCH) {
          p.ast.setLength(astLength);
        } else {
          p.ast.up(op.index, rule.name, phraseIndex, sysData.phraseLength);
        }
      }
    }
  };
  // The `TRG` operator.<br>
  // Succeeds if the single first character of the phrase is
  // within the `min - max` range.
  const opTRG = (opIndex, phraseIndex) => {
    const op = opcodes[opIndex];
    sysData.state = id.NOMATCH;
    if (phraseIndex < chars.length) {
      if (op.min <= chars[phraseIndex] && chars[phraseIndex] <= op.max) {
        sysData.state = id.MATCH;
        sysData.phraseLength = 1;
      }
    }
  };
  // The `TBS` operator.<br>
  // Matches its pre-defined phrase against the input string.
  // All characters must match exactly.
  // Case-sensitive literal strings (`'string'` & `%s"string"`) are translated to `TBS`
  // operators by `apg`.
  // Phrase length of zero is not allowed.
  // Empty phrases can only be defined with `TLS` operators.
  const opTBS = (opIndex, phraseIndex) => {
    const op = opcodes[opIndex];
    const len = op.string.length;
    sysData.state = id.NOMATCH;
    if (phraseIndex + len <= chars.length) {
      for (let i = 0; i < len; i += 1) {
        if (chars[phraseIndex + i] !== op.string[i]) {
          return;
        }
      }
      sysData.state = id.MATCH;
      sysData.phraseLength = len;
    } /* implied else NOMATCH */
  };
  // The `TLS` operator.<br>
  // Matches its pre-defined phrase against the input string.
  // A case-insensitive match is attempted for ASCII alphbetical characters.
  // `TLS` is the only operator that explicitly allows empty phrases.
  // `apg` will fail for empty `TBS`, case-sensitive strings (`''`) or
  // zero repetitions (`0*0RuleName` or `0RuleName`).
  const opTLS = (opIndex, phraseIndex) => {
    let code;
    const op = opcodes[opIndex];
    sysData.state = id.NOMATCH;
    const len = op.string.length;
    if (len === 0) {
      /* EMPTY match allowed for TLS */
      sysData.state = id.EMPTY;
      return;
    }
    if (phraseIndex + len <= chars.length) {
      for (let i = 0; i < len; i += 1) {
        code = chars[phraseIndex + i];
        if (code >= 65 && code <= 90) {
          code += 32;
        }
        if (code !== op.string[i]) {
          return;
        }
      }
      sysData.state = id.MATCH;
      sysData.phraseLength = len;
    } /* implied else NOMATCH */
  };
  // Validate the callback function's returned sysData values.
  // It's the user's responsibility to get it right but `UDT` fails if not.
  const validateUdtCallbackResult = (udt, sysData, charsLeft) => {
    if (sysData.phraseLength > charsLeft) {
      let str = `${thisFileName}opUDT(${udt.name}): callback function error: `;
      str += `sysData.phraseLength: ${sysData.phraseLength}`;
      str += ` must be <= remaining chars: ${charsLeft}`;
      throw new Error(str);
    }
    switch (sysData.state) {
      case id.ACTIVE:
        throw new Error(`${thisFileName}opUDT(${udt.name}) ACTIVE state return not allowed.`);
      case id.EMPTY:
        if (udt.empty) {
          sysData.phraseLength = 0;
        } else {
          throw new Error(`${thisFileName}opUDT(${udt.name}) may not return EMPTY.`);
        }
        break;
      case id.MATCH:
        if (sysData.phraseLength === 0) {
          if (udt.empty) {
            sysData.state = id.EMPTY;
          } else {
            throw new Error(`${thisFileName}opUDT(${udt.name}) may not return EMPTY.`);
          }
        }
        break;
      case id.NOMATCH:
        sysData.phraseLength = 0;
        break;
      default:
        throw new Error(
          `${thisFileName}opUDT(${udt.name}): callback function return error. Unrecognized return state: ${sysData.state}`
        );
    }
  };
  // The `UDT` operator.<br>
  // Simply calls the user's callback function, but operates like `RNM` with regard to the `AST`
  // and back referencing.
  // There is some ambiguity here. `UDT`s act as terminals for phrase recognition but as named rules
  // for `AST` nodes and back referencing.
  // See [`ast.js`](./ast.html) for usage.
  const opUDT = (opIndex, phraseIndex) => {
    let astLength;
    let astIndex;
    let astDefined;
    const op = opcodes[opIndex];
    const udt = udts[op.index];
    sysData.UdtIndex = udt.index;
    /* ignore AST in look ahead */
    if (!lookAhead) {
      astDefined = p.ast && p.ast.udtDefined(op.index);
      if (astDefined) {
        astIndex = rules.length + op.index;
        astLength = p.ast.getLength();
        p.ast.down(astIndex, udt.name);
      }
    }
    /* call the UDT */
    const charsLeft = chars.length - phraseIndex;
    udtCallbacks[op.index](sysData, chars, phraseIndex, userData);
    validateUdtCallbackResult(udt, sysData, charsLeft);
    if (!lookAhead) {
      /* end AST */
      if (astDefined) {
        if (sysData.state === id.NOMATCH) {
          p.ast.setLength(astLength);
        } else {
          p.ast.up(astIndex, udt.name, phraseIndex, sysData.phraseLength);
        }
      }
    }
  };
  // The `AND` operator.<br>
  // This is the positive `look ahead` operator.
  // Executes its single child node, returning the EMPTY state
  // if it succeedsand NOMATCH if it fails.
  // *Always* backtracks on any matched phrase and returns EMPTY on success.
  const opAND = (opIndex, phraseIndex) => {
    lookAhead += 1;
    opExecute(opIndex + 1, phraseIndex);
    lookAhead -= 1;
    sysData.phraseLength = 0;
    switch (sysData.state) {
      case id.EMPTY:
        sysData.state = id.EMPTY;
        break;
      case id.MATCH:
        sysData.state = id.EMPTY;
        break;
      case id.NOMATCH:
        sysData.state = id.NOMATCH;
        break;
      default:
        throw new Error(`opAND: invalid state ${sysData.state}`);
    }
  };
  // The `NOT` operator.<br>
  // This is the negative `look ahead` operator.
  // Executes its single child node, returning the EMPTY state
  // if it *fails* and NOMATCH if it succeeds.
  // *Always* backtracks on any matched phrase and returns EMPTY
  // on success (failure of its child node).
  const opNOT = (opIndex, phraseIndex) => {
    lookAhead += 1;
    opExecute(opIndex + 1, phraseIndex);
    lookAhead -= 1;
    sysData.phraseLength = 0;
    switch (sysData.state) {
      case id.EMPTY:
      case id.MATCH:
        sysData.state = id.NOMATCH;
        break;
      case id.NOMATCH:
        sysData.state = id.EMPTY;
        break;
      default:
        throw new Error(`opNOT: invalid state ${sysData.state}`);
    }
  };

  const opExecute = (opIndex, phraseIndex) => {
    const functionName = `${thisFileName}opExecute(): `;
    const op = opcodes[opIndex];
    nodeHits += 1;
    if (treeDepth > maxTreeDepth) {
      maxTreeDepth = treeDepth;
    }
    treeDepth += 1;
    sysData.refresh();
    if (p.trace) {
      p.trace.down(op, phraseIndex);
    }
    switch (op.type) {
      case id.ALT:
        opALT(opIndex, phraseIndex);
        break;
      case id.CAT:
        opCAT(opIndex, phraseIndex);
        break;
      case id.REP:
        opREP(opIndex, phraseIndex);
        break;
      case id.RNM:
        opRNM(opIndex, phraseIndex);
        break;
      case id.TRG:
        opTRG(opIndex, phraseIndex);
        break;
      case id.TBS:
        opTBS(opIndex, phraseIndex);
        break;
      case id.TLS:
        opTLS(opIndex, phraseIndex);
        break;
      case id.UDT:
        opUDT(opIndex, phraseIndex);
        break;
      case id.AND:
        opAND(opIndex, phraseIndex);
        break;
      case id.NOT:
        opNOT(opIndex, phraseIndex);
        break;
      default:
        throw new Error(`${functionName}unrecognized operator`);
    }
    if (!lookAhead) {
      if (phraseIndex + sysData.phraseLength > maxMatched) {
        maxMatched = phraseIndex + sysData.phraseLength;
      }
    }
    if (p.stats) {
      p.stats.collect(op, sysData);
    }
    if (p.trace) {
      p.trace.up(op, sysData.state, phraseIndex, sysData.phraseLength);
    }
    treeDepth -= 1;
  };
};

const utilities = {
  // utility functions
  stringToChars: (string) => [...string].map((cp) => cp.codePointAt(0)),
  charsToString: (chars, beg, len) => {
    let subChars = chars;
    while (1) {
      if (beg === undefined || beg < 0) {
        break;
      }
      if (len === undefined) {
        subChars = chars.slice(beg);
        break;
      }
      if (len <= 0) {
        // always an empty string
        return '';
      }
      subChars = chars.slice(beg, beg + len);
      break;
    }
    return String.fromCodePoint(...subChars);
  },
};

const identifiers = {
  // Identifies the operator type.
  // NB: These must match the values in apg-js 4.3.0, apg-lib/identifiers.
  /* the original ABNF operators */
  ALT: 1 /* alternation */,
  CAT: 2 /* concatenation */,
  REP: 3 /* repetition */,
  RNM: 4 /* rule name */,
  TRG: 5 /* terminal range */,
  TBS: 6 /* terminal binary string, case sensitive */,
  TLS: 7 /* terminal literal string, case insensitive */,
  /* the super set, SABNF operators */
  UDT: 11 /* user-defined terminal */,
  AND: 12 /* positive look ahead */,
  NOT: 13 /* negative look ahead */,
  // Used by the parser and the user's `RNM` and `UDT` callback functions.
  // Identifies the parser state as it traverses the parse tree nodes.
  // - *ACTIVE* - indicates the downward direction through the parse tree node.
  // - *MATCH* - indicates the upward direction and a phrase, of length \> 0, has been successfully matched
  // - *EMPTY* - indicates the upward direction and a phrase, of length = 0, has been successfully matched
  // - *NOMATCH* - indicates the upward direction and the parser failed to match any phrase at all
  ACTIVE: 100,
  MATCH: 101,
  EMPTY: 102,
  NOMATCH: 103,
  // Used by [`AST` translator](./ast.html) (semantic analysis) and the user's callback functions
  // to indicate the direction of flow through the `AST` nodes.
  // - *SEM_PRE* - indicates the downward (pre-branch) direction through the `AST` node.
  // - *SEM_POST* - indicates the upward (post-branch) direction through the `AST` node.
  SEM_PRE: 200,
  SEM_POST: 201,
  // Ignored. Retained for backwords compatibility.
  SEM_OK: 300,
  idName: (s) => {
    switch (s) {
      case identifiers.ALT:
        return 'ALT';
      case identifiers.CAT:
        return 'CAT';
      case identifiers.REP:
        return 'REP';
      case identifiers.RNM:
        return 'RNM';
      case identifiers.TRG:
        return 'TRG';
      case identifiers.TBS:
        return 'TBS';
      case identifiers.TLS:
        return 'TLS';
      case identifiers.UDT:
        return 'UDT';
      case identifiers.AND:
        return 'AND';
      case identifiers.NOT:
        return 'NOT';
      case identifiers.ACTIVE:
        return 'ACTIVE';
      case identifiers.EMPTY:
        return 'EMPTY';
      case identifiers.MATCH:
        return 'MATCH';
      case identifiers.NOMATCH:
        return 'NOMATCH';
      case identifiers.SEM_PRE:
        return 'SEM_PRE';
      case identifiers.SEM_POST:
        return 'SEM_POST';
      case identifiers.SEM_OK:
        return 'SEM_OK';
      default:
        return 'UNRECOGNIZED STATE';
    }
  },
};
