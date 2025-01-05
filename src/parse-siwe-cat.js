const parseSiwe = (function () {
  function parseSiweMessage(msg, erc55 = 'validate') {
    const fname = 'parseSiweMessage: ';
    if (typeof msg !== 'string') {
      throw new Error(`${fname} invalid input msg: message must be of type string`);
    }
    const p = new Parser();
    const g = new Grammar();

    // set the parser's callback functions
    p.callbacks['ffscheme'] = cb.ffscheme;
    p.callbacks['fdomain'] = cb.fdomain;
    p.callbacks['faddress'] = cb.faddress;
    p.callbacks['fstatement'] = cb.fstatement;
    p.callbacks['furi'] = cb.furi;
    p.callbacks['fnonce'] = cb.fnonce;
    p.callbacks['fversion'] = cb.fversion;
    p.callbacks['fchain-id'] = cb.fchainId;
    p.callbacks['fissued-at'] = cb.fissuedAt;
    p.callbacks['fexpiration-time'] = cb.fexpirationTime;
    p.callbacks['fnot-before'] = cb.fnotBefore;
    p.callbacks['frequest-id'] = cb.frequestId;
    p.callbacks['fresources'] = cb.fresources;
    p.callbacks['fresource'] = cb.fresource;
    p.callbacks['empty-statement'] = cb.emptyStatement;
    p.callbacks['no-statement'] = cb.noStatement;
    p.callbacks['actual-statement'] = cb.actualStatment;
    p.callbacks['pre-uri'] = cb.preUri;
    p.callbacks['pre-version'] = cb.preVersion;
    p.callbacks['pre-chain-id'] = cb.preChainId;
    p.callbacks['pre-nonce'] = cb.preNonce;
    p.callbacks['pre-issued-at'] = cb.preIssuedAt;
    // URI callbacks
    p.callbacks['uri'] = cb.URI;
    p.callbacks['scheme'] = cb.scheme;
    p.callbacks['userinfo-at'] = cb.userinfo;
    p.callbacks['host'] = cb.host;
    p.callbacks['IP-literal'] = cb.ipLiteral;
    p.callbacks['port'] = cb.port;
    p.callbacks['path-abempty'] = cb.pathAbempty;
    p.callbacks['path-absolute'] = cb.pathAbsolute;
    p.callbacks['path-rootless'] = cb.pathRootless;
    p.callbacks['path-empty'] = cb.pathEmpty;
    p.callbacks['query'] = cb.query;
    p.callbacks['fragment'] = cb.fragment;
    p.callbacks['IPv4address'] = cb.ipv4;
    p.callbacks['nodcolon'] = cb.nodcolon;
    p.callbacks['dcolon'] = cb.dcolon;
    p.callbacks['h16'] = cb.h16;
    p.callbacks['h16c'] = cb.h16;
    p.callbacks['h16n'] = cb.h16;
    p.callbacks['h16cn'] = cb.h16;
    p.callbacks['dec-octet'] = cb.decOctet;
    p.callbacks['dec-digit'] = cb.decDigit;

    // BEGIN: some parser helper functions
    function validateDateTime(time, name = 'unknown') {
      const ret = p.parse(g, 'date-time', time);
      if (!ret.success || isNaN(Date.parse(time))) {
        throw new Error(`${fname}invalid date time: ${name} not date time string format: ${time}`);
      }
    }
    function validInt(i) {
      const valid = parseInt(i, 10);
      if (isNaN(valid)) {
        throw new Error(`${fname}invalid integer: not a number: ${i}`);
      } else if (valid === Infinity) {
        throw new Error(`${fname}invalid integer: Infinity: ${i}`);
      }
      return valid;
    }

    // Validates an RFC 3986 URI.
    // returns true if the URI is valid, false otherwise
    function isUri(URI) {
      ret = p.parse(g, 'uri', URI, {});
      return ret.success;
    }
    // END: some parser helper functions

    // first pass parse of the message
    // capture all the message parts, then validate them one-by-one later
    let data = { error: false };
    let ret;
    ret = p.parse(g, 'siwe-first-pass', msg, data);
    if (data.error) {
      throw new Error(`${fname}invalid siwe message: ${data.error}`);
    }
    if (!ret.success) {
      throw new Error(
        `${fname}invalid siwe message: carefully check message syntax, especially after required "Issued At: "\n${JSON.stringify(
          ret
        )}`
      );
    }

    if (data.fscheme) {
      // validate the scheme
      ret = p.parse(g, 'scheme', data.fscheme, {});
      if (!ret.success) {
        throw new Error(`${fname}invalid scheme: ${data.fscheme}`);
      }
    }

    // validate the domain
    ret = p.parse(g, 'authority', data.fdomain, {});
    if (!ret.success) {
      throw new Error(`${fname}invalid domain: ${data.fdomain}`);
    }

    // validate the address
    ret = p.parse(g, 'address', data.faddress);
    if (!ret.success) {
      throw new Error(`${fname}invalid address: ${data.faddress}`);
    }
    if (erc55 == 'validate') {
      // address must be ERC55 format
      if (!isERC55(data.faddress)) {
        throw new Error(
          `${fname}invalid ERC-55 format address: 'validate' specified, MUST be ERC55-conformant: ${data.faddress}`
        );
      }
    } else if (erc55 === 'convert') {
      // convert address to ERC55 format
      data.faddress = toERC55(data.faddress);
    }
    // else for any other value of erc55 no further action on the address is taken

    // validate the statement
    if (data.fstatement !== undefined && data.fstatement !== '') {
      ret = p.parse(g, 'statement', data.fstatement);
      if (!ret.success) {
        throw new Error(`${fname}invalid statement: ${data.fstatement}`);
      }
    }

    // validate the URI
    if (!isUri(data.furi)) {
      throw new Error(`${fname}invalid URI: ${data.furi}`);
    }

    // validate the version
    ret = p.parse(g, 'version', data.fversion);
    if (!ret.success) {
      throw new Error(`${fname}invalid Version: ${data.fversion}`);
    }
    data.fversion = validInt(data.fversion);

    // validate the chain-id
    ret = p.parse(g, 'chain-id', data.fchainId);
    if (!ret.success) {
      throw new Error(`${fname}invalid Chain ID: ${data.fchainId}`);
    }
    data.fchainId = validInt(data.fchainId);

    // validate nonce
    ret = p.parse(g, 'nonce', data.fnonce);
    if (!ret.success) {
      throw new Error(`${fname}invalid Nonce: ${data.fnonce}`);
    }

    // validate the date times
    validateDateTime(data.fissuedAt, 'Issued At');
    if (data.fexpirationTime) {
      validateDateTime(data.fexpirationTime, 'Expiration Time');
    }
    if (data.fnotBefore) {
      validateDateTime(data.fnotBefore, 'Not Before');
    }

    // validate request-id
    if (data.frequestId !== undefined && data.frequestId !== '') {
      ret = p.parse(g, 'request-id', data.frequestId);
      if (!ret.success) {
        throw new Error(`${fname}invalid Request ID: i${data.frequestId}`);
      }
    }

    // validate all resource URIs, if any
    if (data.fresources && data.fresources.length) {
      for (let i = 0; i < data.fresources.length; i++) {
        if (!isUri(data.fresources[i])) {
          throw new Error(`${fname}invalid resource URI [${i}]: ${data.fresources[i]}`);
        }
      }
    }

    // by now all first-pass values (e.g. fscheme) have been validated
    const o = {};
    o.scheme = data.fscheme;
    o.domain = data.fdomain;
    o.address = data.faddress;
    o.statement = data.fstatement;
    o.uri = data.furi;
    o.version = data.fversion;
    o.chainId = data.fchainId;
    o.nonce = data.fnonce;
    o.issuedAt = data.fissuedAt;
    o.expirationTime = data.fexpirationTime;
    o.notBefore = data.fnotBefore;
    o.requestId = data.frequestId;
    o.resources = undefined;
    if (data.fresources) {
      o.resources = [];
      for (let i = 0; i < data.fresources.length; i++) {
        o.resources.push(data.fresources[i]);
      }
    }
    return o;
  }

  /**
   * Parses a Uniform Resource Identifier (URI) defined in [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986).
   *
   * @param {string} URI the URI to parse
   * @returns `false` if the URI is invalid, otherwise a URI object. e.g.<br>
   * ````
   * const obj = isUri('uri://user:pass@example.com:123/one/two.three?q1=a1&q2=a2#body');
   * ````
   * returns:
   * ````
   * obj.scheme = 'uri'
   * obj.userinfo = 'user:pass'
   * obj.host = 'example.com',
   * obj.port = 123,
   * obj.path = '/one/two.three',
   * obj.query = 'q1=a1&q2=a2',
   * obj.fragment = 'body'
   * ````
   */
  function isUri(URI) {
    const p = new Parser();
    const g = new Grammar();
    const uriData = {};
    p.callbacks['uri'] = cb.URI;
    p.callbacks['scheme'] = cb.scheme;
    p.callbacks['userinfo-at'] = cb.userinfo;
    p.callbacks['host'] = cb.host;
    p.callbacks['IP-literal'] = cb.ipLiteral;
    p.callbacks['port'] = cb.port;
    p.callbacks['path-abempty'] = cb.pathAbempty;
    p.callbacks['path-absolute'] = cb.pathAbsolute;
    p.callbacks['path-rootless'] = cb.pathRootless;
    p.callbacks['path-empty'] = cb.pathEmpty;
    p.callbacks['query'] = cb.query;
    p.callbacks['fragment'] = cb.fragment;
    p.callbacks['IPv4address'] = cb.ipv4;
    p.callbacks['nodcolon'] = cb.nodcolon;
    p.callbacks['dcolon'] = cb.dcolon;
    p.callbacks['h16'] = cb.h16;
    p.callbacks['h16c'] = cb.h16;
    p.callbacks['h16n'] = cb.h16;
    p.callbacks['h16cn'] = cb.h16;
    p.callbacks['dec-octet'] = cb.decOctet;
    p.callbacks['dec-digit'] = cb.decDigit;
    const ret = p.parse(g, 'uri', URI, uriData);
    if (!ret.success) {
      return false;
    }
    const uriObject = {
      uri: uriData['uri'],
      scheme: uriData['scheme'],
      userinfo: uriData['userinfo'],
      host: uriData['host'],
      port: uriData['port'],
      path: uriData['path'],
      query: uriData['query'],
      fragment: uriData['fragment'],
    };
    return uriObject;
  }

  /**
   * Stringify an [ERC-4361: Sign-In with Ethereum](https://eips.ethereum.org/EIPS/eip-4361) (siwe) object.
   *
   * @param {object} o an siwe message object (see {@link parseSiweMessage} )
   * @returns A stringified version of the object suitable as input to {@link parseSiweMessage}.
   *
   * For example, to validate an siwe object <br>*(ignore backslash, JSDoc can't handle closed bracket character without it)*:
   * ````
   * try{
   *  parseSiweMessage(siweObjectToString(siweObject));
   *  console.log('siweObject is valid');
   * \}catch(e){
   *  console.log('siweObject is not valid: ' + e.message);
   * \}
   * ````
   */
  function siweObjectToString(o) {
    let str = '';
    if (o.scheme && o.scheme !== '') {
      str += `${o.scheme}://`;
    }
    if (o.domain && o.domain !== '') {
      str += o.domain;
    }
    str += ' wants you to sign in with your Ethereum account:\n';
    if (o.address && o.address !== '') {
      str += `${o.address}\n`;
    }
    str += '\n';
    if (o.statement !== undefined) {
      str += `${o.statement}\n`;
    }
    str += '\n';
    if (o.uri && o.uri !== '') {
      str += `URI: ${o.uri}\n`;
    }
    if (o['version'] && o['version'] !== '') {
      str += `Version: ${o['version']}\n`;
    }
    if (o['chainId'] && o['chainId'] !== '') {
      str += `Chain ID: ${o['chainId']}\n`;
    }
    if (o['nonce'] && o['nonce'] !== '') {
      str += `Nonce: ${o['nonce']}\n`;
    }
    if (o['issuedAt'] && o['issuedAt'] !== '') {
      str += `Issued At: ${o['issuedAt']}`;
    }
    if (o['expirationTime'] && o['expirationTime'] !== '') {
      str += `\nExpiration Time: ${o['expirationTime']}`;
    }
    if (o['notBefore'] && o['notBefore'] !== '') {
      str += `\nNot Before: ${o['notBefore']}`;
    }
    if (o['requestId'] !== undefined) {
      str += `\nRequest ID: ${o['requestId']}`;
    }
    if (o['resources']) {
      str += `\nResources:`;
      if (Array.isArray(o.resources)) {
        for (let i = 0; i < o.resources.length; i++) {
          str += `\n- ${o.resources[i]}`;
        }
      }
    }
    return str;
  }

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
  // copyright: Copyright (c) 2024 Lowell D. Thomas, all rights reserved<br>
  //   license: BSD-2-Clause (https://opensource.org/licenses/BSD-2-Clause)<br>
  //
  // Generated by apg-js, Version 4.4.0 [apg-js](https://github.com/ldthomas/apg-js)
  function Grammar() {
    // ```
    // SUMMARY
    //      rules = 83
    //       udts = 0
    //    opcodes = 447
    //        ---   ABNF original opcodes
    //        ALT = 43
    //        CAT = 48
    //        REP = 63
    //        RNM = 94
    //        TLS = 7
    //        TBS = 94
    //        TRG = 95
    //        ---   SABNF superset opcodes
    //        UDT = 0
    //        AND = 0
    //        NOT = 3
    // characters = [0 - 127]
    // ```
    /* OBJECT IDENTIFIER (for internal parser use) */
    this.grammarObject = 'grammarObject';

    /* RULES */
    this.rules = [];
    this.rules[0] = { name: 'siwe-first-pass', lower: 'siwe-first-pass', index: 0, isBkr: false };
    this.rules[1] = { name: 'pre-uri', lower: 'pre-uri', index: 1, isBkr: false };
    this.rules[2] = { name: 'pre-version', lower: 'pre-version', index: 2, isBkr: false };
    this.rules[3] = { name: 'pre-chain-id', lower: 'pre-chain-id', index: 3, isBkr: false };
    this.rules[4] = { name: 'pre-nonce', lower: 'pre-nonce', index: 4, isBkr: false };
    this.rules[5] = { name: 'pre-issued-at', lower: 'pre-issued-at', index: 5, isBkr: false };
    this.rules[6] = { name: 'ffscheme', lower: 'ffscheme', index: 6, isBkr: false };
    this.rules[7] = { name: 'fdomain', lower: 'fdomain', index: 7, isBkr: false };
    this.rules[8] = { name: 'fissued-at', lower: 'fissued-at', index: 8, isBkr: false };
    this.rules[9] = { name: 'fexpiration-time', lower: 'fexpiration-time', index: 9, isBkr: false };
    this.rules[10] = { name: 'fnot-before', lower: 'fnot-before', index: 10, isBkr: false };
    this.rules[11] = { name: 'furi', lower: 'furi', index: 11, isBkr: false };
    this.rules[12] = { name: 'fscheme', lower: 'fscheme', index: 12, isBkr: false };
    this.rules[13] = { name: 'faddress', lower: 'faddress', index: 13, isBkr: false };
    this.rules[14] = { name: 'fstatement', lower: 'fstatement', index: 14, isBkr: false };
    this.rules[15] = { name: 'fversion', lower: 'fversion', index: 15, isBkr: false };
    this.rules[16] = { name: 'fchain-id', lower: 'fchain-id', index: 16, isBkr: false };
    this.rules[17] = { name: 'fnonce', lower: 'fnonce', index: 17, isBkr: false };
    this.rules[18] = { name: 'frequest-id', lower: 'frequest-id', index: 18, isBkr: false };
    this.rules[19] = { name: 'fresources', lower: 'fresources', index: 19, isBkr: false };
    this.rules[20] = { name: 'fresource', lower: 'fresource', index: 20, isBkr: false };
    this.rules[21] = { name: 'no-statement', lower: 'no-statement', index: 21, isBkr: false };
    this.rules[22] = { name: 'empty-statement', lower: 'empty-statement', index: 22, isBkr: false };
    this.rules[23] = { name: 'actual-statement', lower: 'actual-statement', index: 23, isBkr: false };
    this.rules[24] = { name: 'domain', lower: 'domain', index: 24, isBkr: false };
    this.rules[25] = { name: 'address', lower: 'address', index: 25, isBkr: false };
    this.rules[26] = { name: 'statement', lower: 'statement', index: 26, isBkr: false };
    this.rules[27] = { name: 'version', lower: 'version', index: 27, isBkr: false };
    this.rules[28] = { name: 'chain-id', lower: 'chain-id', index: 28, isBkr: false };
    this.rules[29] = { name: 'nonce', lower: 'nonce', index: 29, isBkr: false };
    this.rules[30] = { name: 'issued-at', lower: 'issued-at', index: 30, isBkr: false };
    this.rules[31] = { name: 'expiration-time', lower: 'expiration-time', index: 31, isBkr: false };
    this.rules[32] = { name: 'not-before', lower: 'not-before', index: 32, isBkr: false };
    this.rules[33] = { name: 'request-id', lower: 'request-id', index: 33, isBkr: false };
    this.rules[34] = { name: 'resources', lower: 'resources', index: 34, isBkr: false };
    this.rules[35] = { name: 'resource', lower: 'resource', index: 35, isBkr: false };
    this.rules[36] = { name: 'date-fullyear', lower: 'date-fullyear', index: 36, isBkr: false };
    this.rules[37] = { name: 'date-month', lower: 'date-month', index: 37, isBkr: false };
    this.rules[38] = { name: 'date-mday', lower: 'date-mday', index: 38, isBkr: false };
    this.rules[39] = { name: 'time-hour', lower: 'time-hour', index: 39, isBkr: false };
    this.rules[40] = { name: 'time-minute', lower: 'time-minute', index: 40, isBkr: false };
    this.rules[41] = { name: 'time-second', lower: 'time-second', index: 41, isBkr: false };
    this.rules[42] = { name: 'time-secfrac', lower: 'time-secfrac', index: 42, isBkr: false };
    this.rules[43] = { name: 'time-numoffset', lower: 'time-numoffset', index: 43, isBkr: false };
    this.rules[44] = { name: 'time-offset', lower: 'time-offset', index: 44, isBkr: false };
    this.rules[45] = { name: 'partial-time', lower: 'partial-time', index: 45, isBkr: false };
    this.rules[46] = { name: 'full-date', lower: 'full-date', index: 46, isBkr: false };
    this.rules[47] = { name: 'full-time', lower: 'full-time', index: 47, isBkr: false };
    this.rules[48] = { name: 'date-time', lower: 'date-time', index: 48, isBkr: false };
    this.rules[49] = { name: 'URI', lower: 'uri', index: 49, isBkr: false };
    this.rules[50] = { name: 'hier-part', lower: 'hier-part', index: 50, isBkr: false };
    this.rules[51] = { name: 'authority', lower: 'authority', index: 51, isBkr: false };
    this.rules[52] = { name: 'path-abempty', lower: 'path-abempty', index: 52, isBkr: false };
    this.rules[53] = { name: 'path-absolute', lower: 'path-absolute', index: 53, isBkr: false };
    this.rules[54] = { name: 'path-rootless', lower: 'path-rootless', index: 54, isBkr: false };
    this.rules[55] = { name: 'path-empty', lower: 'path-empty', index: 55, isBkr: false };
    this.rules[56] = { name: 'userinfo-at', lower: 'userinfo-at', index: 56, isBkr: false };
    this.rules[57] = { name: 'userinfo', lower: 'userinfo', index: 57, isBkr: false };
    this.rules[58] = { name: 'host', lower: 'host', index: 58, isBkr: false };
    this.rules[59] = { name: 'IP-literal', lower: 'ip-literal', index: 59, isBkr: false };
    this.rules[60] = { name: 'IPvFuture', lower: 'ipvfuture', index: 60, isBkr: false };
    this.rules[61] = { name: 'IPv6address', lower: 'ipv6address', index: 61, isBkr: false };
    this.rules[62] = { name: 'nodcolon', lower: 'nodcolon', index: 62, isBkr: false };
    this.rules[63] = { name: 'dcolon', lower: 'dcolon', index: 63, isBkr: false };
    this.rules[64] = { name: 'h16', lower: 'h16', index: 64, isBkr: false };
    this.rules[65] = { name: 'h16c', lower: 'h16c', index: 65, isBkr: false };
    this.rules[66] = { name: 'h16n', lower: 'h16n', index: 66, isBkr: false };
    this.rules[67] = { name: 'h16cn', lower: 'h16cn', index: 67, isBkr: false };
    this.rules[68] = { name: 'IPv4address', lower: 'ipv4address', index: 68, isBkr: false };
    this.rules[69] = { name: 'dec-octet', lower: 'dec-octet', index: 69, isBkr: false };
    this.rules[70] = { name: 'dec-digit', lower: 'dec-digit', index: 70, isBkr: false };
    this.rules[71] = { name: 'reg-name', lower: 'reg-name', index: 71, isBkr: false };
    this.rules[72] = { name: 'reg-name-char', lower: 'reg-name-char', index: 72, isBkr: false };
    this.rules[73] = { name: 'port', lower: 'port', index: 73, isBkr: false };
    this.rules[74] = { name: 'query', lower: 'query', index: 74, isBkr: false };
    this.rules[75] = { name: 'fragment', lower: 'fragment', index: 75, isBkr: false };
    this.rules[76] = { name: 'segment', lower: 'segment', index: 76, isBkr: false };
    this.rules[77] = { name: 'segment-nz', lower: 'segment-nz', index: 77, isBkr: false };
    this.rules[78] = { name: 'scheme', lower: 'scheme', index: 78, isBkr: false };
    this.rules[79] = { name: 'pchar', lower: 'pchar', index: 79, isBkr: false };
    this.rules[80] = { name: 'pct-encoded', lower: 'pct-encoded', index: 80, isBkr: false };
    this.rules[81] = { name: 'unreserved', lower: 'unreserved', index: 81, isBkr: false };
    this.rules[82] = { name: 'reserved', lower: 'reserved', index: 82, isBkr: false };

    /* UDTS */
    this.udts = [];

    /* OPCODES */
    /* siwe-first-pass */
    this.rules[0].opcodes = [];
    this.rules[0].opcodes[0] = {
      type: 2,
      children: [1, 3, 4, 5, 6, 7, 8, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 31, 36, 41],
    }; // CAT
    this.rules[0].opcodes[1] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[0].opcodes[2] = { type: 4, index: 6 }; // RNM(ffscheme)
    this.rules[0].opcodes[3] = { type: 4, index: 7 }; // RNM(fdomain)
    this.rules[0].opcodes[4] = {
      type: 6,
      string: [
        32, 119, 97, 110, 116, 115, 32, 121, 111, 117, 32, 116, 111, 32, 115, 105, 103, 110, 32, 105, 110, 32, 119, 105,
        116, 104, 32, 121, 111, 117, 114, 32, 69, 116, 104, 101, 114, 101, 117, 109, 32, 97, 99, 99, 111, 117, 110, 116,
        58,
      ],
    }; // TBS
    this.rules[0].opcodes[5] = { type: 6, string: [10] }; // TBS
    this.rules[0].opcodes[6] = { type: 4, index: 13 }; // RNM(faddress)
    this.rules[0].opcodes[7] = { type: 6, string: [10] }; // TBS
    this.rules[0].opcodes[8] = { type: 1, children: [9, 10, 11] }; // ALT
    this.rules[0].opcodes[9] = { type: 4, index: 22 }; // RNM(empty-statement)
    this.rules[0].opcodes[10] = { type: 4, index: 21 }; // RNM(no-statement)
    this.rules[0].opcodes[11] = { type: 4, index: 23 }; // RNM(actual-statement)
    this.rules[0].opcodes[12] = { type: 4, index: 1 }; // RNM(pre-uri)
    this.rules[0].opcodes[13] = { type: 4, index: 11 }; // RNM(furi)
    this.rules[0].opcodes[14] = { type: 6, string: [10] }; // TBS
    this.rules[0].opcodes[15] = { type: 4, index: 2 }; // RNM(pre-version)
    this.rules[0].opcodes[16] = { type: 4, index: 15 }; // RNM(fversion)
    this.rules[0].opcodes[17] = { type: 6, string: [10] }; // TBS
    this.rules[0].opcodes[18] = { type: 4, index: 3 }; // RNM(pre-chain-id)
    this.rules[0].opcodes[19] = { type: 4, index: 16 }; // RNM(fchain-id)
    this.rules[0].opcodes[20] = { type: 6, string: [10] }; // TBS
    this.rules[0].opcodes[21] = { type: 4, index: 4 }; // RNM(pre-nonce)
    this.rules[0].opcodes[22] = { type: 4, index: 17 }; // RNM(fnonce)
    this.rules[0].opcodes[23] = { type: 6, string: [10] }; // TBS
    this.rules[0].opcodes[24] = { type: 4, index: 5 }; // RNM(pre-issued-at)
    this.rules[0].opcodes[25] = { type: 4, index: 8 }; // RNM(fissued-at)
    this.rules[0].opcodes[26] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[0].opcodes[27] = { type: 2, children: [28, 29, 30] }; // CAT
    this.rules[0].opcodes[28] = { type: 6, string: [10] }; // TBS
    this.rules[0].opcodes[29] = {
      type: 6,
      string: [69, 120, 112, 105, 114, 97, 116, 105, 111, 110, 32, 84, 105, 109, 101, 58, 32],
    }; // TBS
    this.rules[0].opcodes[30] = { type: 4, index: 9 }; // RNM(fexpiration-time)
    this.rules[0].opcodes[31] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[0].opcodes[32] = { type: 2, children: [33, 34, 35] }; // CAT
    this.rules[0].opcodes[33] = { type: 6, string: [10] }; // TBS
    this.rules[0].opcodes[34] = { type: 6, string: [78, 111, 116, 32, 66, 101, 102, 111, 114, 101, 58, 32] }; // TBS
    this.rules[0].opcodes[35] = { type: 4, index: 10 }; // RNM(fnot-before)
    this.rules[0].opcodes[36] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[0].opcodes[37] = { type: 2, children: [38, 39, 40] }; // CAT
    this.rules[0].opcodes[38] = { type: 6, string: [10] }; // TBS
    this.rules[0].opcodes[39] = { type: 6, string: [82, 101, 113, 117, 101, 115, 116, 32, 73, 68, 58, 32] }; // TBS
    this.rules[0].opcodes[40] = { type: 4, index: 18 }; // RNM(frequest-id)
    this.rules[0].opcodes[41] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[0].opcodes[42] = { type: 2, children: [43, 44, 45] }; // CAT
    this.rules[0].opcodes[43] = { type: 6, string: [10] }; // TBS
    this.rules[0].opcodes[44] = { type: 6, string: [82, 101, 115, 111, 117, 114, 99, 101, 115, 58] }; // TBS
    this.rules[0].opcodes[45] = { type: 4, index: 19 }; // RNM(fresources)

    /* pre-uri */
    this.rules[1].opcodes = [];
    this.rules[1].opcodes[0] = { type: 6, string: [85, 82, 73, 58, 32] }; // TBS

    /* pre-version */
    this.rules[2].opcodes = [];
    this.rules[2].opcodes[0] = { type: 6, string: [86, 101, 114, 115, 105, 111, 110, 58, 32] }; // TBS

    /* pre-chain-id */
    this.rules[3].opcodes = [];
    this.rules[3].opcodes[0] = { type: 6, string: [67, 104, 97, 105, 110, 32, 73, 68, 58, 32] }; // TBS

    /* pre-nonce */
    this.rules[4].opcodes = [];
    this.rules[4].opcodes[0] = { type: 6, string: [78, 111, 110, 99, 101, 58, 32] }; // TBS

    /* pre-issued-at */
    this.rules[5].opcodes = [];
    this.rules[5].opcodes[0] = { type: 6, string: [73, 115, 115, 117, 101, 100, 32, 65, 116, 58, 32] }; // TBS

    /* ffscheme */
    this.rules[6].opcodes = [];
    this.rules[6].opcodes[0] = { type: 2, children: [1, 2] }; // CAT
    this.rules[6].opcodes[1] = { type: 4, index: 12 }; // RNM(fscheme)
    this.rules[6].opcodes[2] = { type: 6, string: [58, 47, 47] }; // TBS

    /* fdomain */
    this.rules[7].opcodes = [];
    this.rules[7].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[7].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[7].opcodes[2] = { type: 5, min: 0, max: 31 }; // TRG
    this.rules[7].opcodes[3] = { type: 5, min: 33, max: 127 }; // TRG

    /* fissued-at */
    this.rules[8].opcodes = [];
    this.rules[8].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[8].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[8].opcodes[2] = { type: 5, min: 0, max: 9 }; // TRG
    this.rules[8].opcodes[3] = { type: 5, min: 11, max: 127 }; // TRG

    /* fexpiration-time */
    this.rules[9].opcodes = [];
    this.rules[9].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[9].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[9].opcodes[2] = { type: 5, min: 0, max: 9 }; // TRG
    this.rules[9].opcodes[3] = { type: 5, min: 11, max: 127 }; // TRG

    /* fnot-before */
    this.rules[10].opcodes = [];
    this.rules[10].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[10].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[10].opcodes[2] = { type: 5, min: 0, max: 9 }; // TRG
    this.rules[10].opcodes[3] = { type: 5, min: 11, max: 127 }; // TRG

    /* furi */
    this.rules[11].opcodes = [];
    this.rules[11].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[11].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[11].opcodes[2] = { type: 5, min: 0, max: 9 }; // TRG
    this.rules[11].opcodes[3] = { type: 5, min: 11, max: 127 }; // TRG

    /* fscheme */
    this.rules[12].opcodes = [];
    this.rules[12].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[12].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[12].opcodes[2] = { type: 5, min: 0, max: 57 }; // TRG
    this.rules[12].opcodes[3] = { type: 5, min: 59, max: 127 }; // TRG

    /* faddress */
    this.rules[13].opcodes = [];
    this.rules[13].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[13].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[13].opcodes[2] = { type: 5, min: 0, max: 9 }; // TRG
    this.rules[13].opcodes[3] = { type: 5, min: 11, max: 127 }; // TRG

    /* fstatement */
    this.rules[14].opcodes = [];
    this.rules[14].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[14].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[14].opcodes[2] = { type: 5, min: 0, max: 9 }; // TRG
    this.rules[14].opcodes[3] = { type: 5, min: 11, max: 127 }; // TRG

    /* fversion */
    this.rules[15].opcodes = [];
    this.rules[15].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[15].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[15].opcodes[2] = { type: 5, min: 0, max: 9 }; // TRG
    this.rules[15].opcodes[3] = { type: 5, min: 11, max: 127 }; // TRG

    /* fchain-id */
    this.rules[16].opcodes = [];
    this.rules[16].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[16].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[16].opcodes[2] = { type: 5, min: 0, max: 9 }; // TRG
    this.rules[16].opcodes[3] = { type: 5, min: 11, max: 127 }; // TRG

    /* fnonce */
    this.rules[17].opcodes = [];
    this.rules[17].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[17].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[17].opcodes[2] = { type: 5, min: 0, max: 9 }; // TRG
    this.rules[17].opcodes[3] = { type: 5, min: 11, max: 127 }; // TRG

    /* frequest-id */
    this.rules[18].opcodes = [];
    this.rules[18].opcodes[0] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[18].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[18].opcodes[2] = { type: 5, min: 0, max: 9 }; // TRG
    this.rules[18].opcodes[3] = { type: 5, min: 11, max: 127 }; // TRG

    /* fresources */
    this.rules[19].opcodes = [];
    this.rules[19].opcodes[0] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[19].opcodes[1] = { type: 2, children: [2, 3] }; // CAT
    this.rules[19].opcodes[2] = { type: 6, string: [10] }; // TBS
    this.rules[19].opcodes[3] = { type: 4, index: 20 }; // RNM(fresource)

    /* fresource */
    this.rules[20].opcodes = [];
    this.rules[20].opcodes[0] = { type: 2, children: [1, 2] }; // CAT
    this.rules[20].opcodes[1] = { type: 7, string: [45, 32] }; // TLS
    this.rules[20].opcodes[2] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[20].opcodes[3] = { type: 1, children: [4, 5] }; // ALT
    this.rules[20].opcodes[4] = { type: 5, min: 0, max: 9 }; // TRG
    this.rules[20].opcodes[5] = { type: 5, min: 11, max: 127 }; // TRG

    /* no-statement */
    this.rules[21].opcodes = [];
    this.rules[21].opcodes[0] = { type: 6, string: [10, 10] }; // TBS

    /* empty-statement */
    this.rules[22].opcodes = [];
    this.rules[22].opcodes[0] = { type: 6, string: [10, 10, 10] }; // TBS

    /* actual-statement */
    this.rules[23].opcodes = [];
    this.rules[23].opcodes[0] = { type: 2, children: [1, 2, 3] }; // CAT
    this.rules[23].opcodes[1] = { type: 6, string: [10] }; // TBS
    this.rules[23].opcodes[2] = { type: 4, index: 14 }; // RNM(fstatement)
    this.rules[23].opcodes[3] = { type: 6, string: [10, 10] }; // TBS

    /* domain */
    this.rules[24].opcodes = [];
    this.rules[24].opcodes[0] = { type: 4, index: 51 }; // RNM(authority)

    /* address */
    this.rules[25].opcodes = [];
    this.rules[25].opcodes[0] = { type: 2, children: [1, 2] }; // CAT
    this.rules[25].opcodes[1] = { type: 6, string: [48, 120] }; // TBS
    this.rules[25].opcodes[2] = { type: 3, min: 40, max: 40 }; // REP
    this.rules[25].opcodes[3] = { type: 1, children: [4, 5, 6] }; // ALT
    this.rules[25].opcodes[4] = { type: 5, min: 48, max: 57 }; // TRG
    this.rules[25].opcodes[5] = { type: 5, min: 65, max: 70 }; // TRG
    this.rules[25].opcodes[6] = { type: 5, min: 97, max: 102 }; // TRG

    /* statement */
    this.rules[26].opcodes = [];
    this.rules[26].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[26].opcodes[1] = { type: 1, children: [2, 3, 4] }; // ALT
    this.rules[26].opcodes[2] = { type: 4, index: 82 }; // RNM(reserved)
    this.rules[26].opcodes[3] = { type: 4, index: 81 }; // RNM(unreserved)
    this.rules[26].opcodes[4] = { type: 7, string: [32] }; // TLS

    /* version */
    this.rules[27].opcodes = [];
    this.rules[27].opcodes[0] = { type: 6, string: [49] }; // TBS

    /* chain-id */
    this.rules[28].opcodes = [];
    this.rules[28].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[28].opcodes[1] = { type: 5, min: 48, max: 57 }; // TRG

    /* nonce */
    this.rules[29].opcodes = [];
    this.rules[29].opcodes[0] = { type: 3, min: 8, max: Infinity }; // REP
    this.rules[29].opcodes[1] = { type: 1, children: [2, 5] }; // ALT
    this.rules[29].opcodes[2] = { type: 1, children: [3, 4] }; // ALT
    this.rules[29].opcodes[3] = { type: 5, min: 97, max: 122 }; // TRG
    this.rules[29].opcodes[4] = { type: 5, min: 65, max: 90 }; // TRG
    this.rules[29].opcodes[5] = { type: 5, min: 48, max: 57 }; // TRG

    /* issued-at */
    this.rules[30].opcodes = [];
    this.rules[30].opcodes[0] = { type: 4, index: 48 }; // RNM(date-time)

    /* expiration-time */
    this.rules[31].opcodes = [];
    this.rules[31].opcodes[0] = { type: 4, index: 48 }; // RNM(date-time)

    /* not-before */
    this.rules[32].opcodes = [];
    this.rules[32].opcodes[0] = { type: 4, index: 48 }; // RNM(date-time)

    /* request-id */
    this.rules[33].opcodes = [];
    this.rules[33].opcodes[0] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[33].opcodes[1] = { type: 4, index: 79 }; // RNM(pchar)

    /* resources */
    this.rules[34].opcodes = [];
    this.rules[34].opcodes[0] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[34].opcodes[1] = { type: 2, children: [2, 3] }; // CAT
    this.rules[34].opcodes[2] = { type: 6, string: [10] }; // TBS
    this.rules[34].opcodes[3] = { type: 4, index: 35 }; // RNM(resource)

    /* resource */
    this.rules[35].opcodes = [];
    this.rules[35].opcodes[0] = { type: 2, children: [1, 2] }; // CAT
    this.rules[35].opcodes[1] = { type: 6, string: [45, 32] }; // TBS
    this.rules[35].opcodes[2] = { type: 4, index: 49 }; // RNM(URI)

    /* date-fullyear */
    this.rules[36].opcodes = [];
    this.rules[36].opcodes[0] = { type: 3, min: 4, max: 4 }; // REP
    this.rules[36].opcodes[1] = { type: 5, min: 48, max: 57 }; // TRG

    /* date-month */
    this.rules[37].opcodes = [];
    this.rules[37].opcodes[0] = { type: 3, min: 2, max: 2 }; // REP
    this.rules[37].opcodes[1] = { type: 5, min: 48, max: 57 }; // TRG

    /* date-mday */
    this.rules[38].opcodes = [];
    this.rules[38].opcodes[0] = { type: 3, min: 2, max: 2 }; // REP
    this.rules[38].opcodes[1] = { type: 5, min: 48, max: 57 }; // TRG

    /* time-hour */
    this.rules[39].opcodes = [];
    this.rules[39].opcodes[0] = { type: 3, min: 2, max: 2 }; // REP
    this.rules[39].opcodes[1] = { type: 5, min: 48, max: 57 }; // TRG

    /* time-minute */
    this.rules[40].opcodes = [];
    this.rules[40].opcodes[0] = { type: 3, min: 2, max: 2 }; // REP
    this.rules[40].opcodes[1] = { type: 5, min: 48, max: 57 }; // TRG

    /* time-second */
    this.rules[41].opcodes = [];
    this.rules[41].opcodes[0] = { type: 3, min: 2, max: 2 }; // REP
    this.rules[41].opcodes[1] = { type: 5, min: 48, max: 57 }; // TRG

    /* time-secfrac */
    this.rules[42].opcodes = [];
    this.rules[42].opcodes[0] = { type: 2, children: [1, 2] }; // CAT
    this.rules[42].opcodes[1] = { type: 6, string: [46] }; // TBS
    this.rules[42].opcodes[2] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[42].opcodes[3] = { type: 5, min: 48, max: 57 }; // TRG

    /* time-numoffset */
    this.rules[43].opcodes = [];
    this.rules[43].opcodes[0] = { type: 2, children: [1, 4, 5, 6] }; // CAT
    this.rules[43].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[43].opcodes[2] = { type: 6, string: [43] }; // TBS
    this.rules[43].opcodes[3] = { type: 6, string: [45] }; // TBS
    this.rules[43].opcodes[4] = { type: 4, index: 39 }; // RNM(time-hour)
    this.rules[43].opcodes[5] = { type: 6, string: [58] }; // TBS
    this.rules[43].opcodes[6] = { type: 4, index: 40 }; // RNM(time-minute)

    /* time-offset */
    this.rules[44].opcodes = [];
    this.rules[44].opcodes[0] = { type: 1, children: [1, 2] }; // ALT
    this.rules[44].opcodes[1] = { type: 7, string: [122] }; // TLS
    this.rules[44].opcodes[2] = { type: 4, index: 43 }; // RNM(time-numoffset)

    /* partial-time */
    this.rules[45].opcodes = [];
    this.rules[45].opcodes[0] = { type: 2, children: [1, 2, 3, 4, 5, 6] }; // CAT
    this.rules[45].opcodes[1] = { type: 4, index: 39 }; // RNM(time-hour)
    this.rules[45].opcodes[2] = { type: 6, string: [58] }; // TBS
    this.rules[45].opcodes[3] = { type: 4, index: 40 }; // RNM(time-minute)
    this.rules[45].opcodes[4] = { type: 6, string: [58] }; // TBS
    this.rules[45].opcodes[5] = { type: 4, index: 41 }; // RNM(time-second)
    this.rules[45].opcodes[6] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[45].opcodes[7] = { type: 4, index: 42 }; // RNM(time-secfrac)

    /* full-date */
    this.rules[46].opcodes = [];
    this.rules[46].opcodes[0] = { type: 2, children: [1, 2, 3, 4, 5] }; // CAT
    this.rules[46].opcodes[1] = { type: 4, index: 36 }; // RNM(date-fullyear)
    this.rules[46].opcodes[2] = { type: 6, string: [45] }; // TBS
    this.rules[46].opcodes[3] = { type: 4, index: 37 }; // RNM(date-month)
    this.rules[46].opcodes[4] = { type: 6, string: [45] }; // TBS
    this.rules[46].opcodes[5] = { type: 4, index: 38 }; // RNM(date-mday)

    /* full-time */
    this.rules[47].opcodes = [];
    this.rules[47].opcodes[0] = { type: 2, children: [1, 2] }; // CAT
    this.rules[47].opcodes[1] = { type: 4, index: 45 }; // RNM(partial-time)
    this.rules[47].opcodes[2] = { type: 4, index: 44 }; // RNM(time-offset)

    /* date-time */
    this.rules[48].opcodes = [];
    this.rules[48].opcodes[0] = { type: 2, children: [1, 2, 3] }; // CAT
    this.rules[48].opcodes[1] = { type: 4, index: 46 }; // RNM(full-date)
    this.rules[48].opcodes[2] = { type: 7, string: [116] }; // TLS
    this.rules[48].opcodes[3] = { type: 4, index: 47 }; // RNM(full-time)

    /* URI */
    this.rules[49].opcodes = [];
    this.rules[49].opcodes[0] = { type: 2, children: [1, 2, 3, 4, 8] }; // CAT
    this.rules[49].opcodes[1] = { type: 4, index: 78 }; // RNM(scheme)
    this.rules[49].opcodes[2] = { type: 6, string: [58] }; // TBS
    this.rules[49].opcodes[3] = { type: 4, index: 50 }; // RNM(hier-part)
    this.rules[49].opcodes[4] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[49].opcodes[5] = { type: 2, children: [6, 7] }; // CAT
    this.rules[49].opcodes[6] = { type: 6, string: [63] }; // TBS
    this.rules[49].opcodes[7] = { type: 4, index: 74 }; // RNM(query)
    this.rules[49].opcodes[8] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[49].opcodes[9] = { type: 2, children: [10, 11] }; // CAT
    this.rules[49].opcodes[10] = { type: 6, string: [35] }; // TBS
    this.rules[49].opcodes[11] = { type: 4, index: 75 }; // RNM(fragment)

    /* hier-part */
    this.rules[50].opcodes = [];
    this.rules[50].opcodes[0] = { type: 1, children: [1, 5, 6, 7] }; // ALT
    this.rules[50].opcodes[1] = { type: 2, children: [2, 3, 4] }; // CAT
    this.rules[50].opcodes[2] = { type: 6, string: [47, 47] }; // TBS
    this.rules[50].opcodes[3] = { type: 4, index: 51 }; // RNM(authority)
    this.rules[50].opcodes[4] = { type: 4, index: 52 }; // RNM(path-abempty)
    this.rules[50].opcodes[5] = { type: 4, index: 53 }; // RNM(path-absolute)
    this.rules[50].opcodes[6] = { type: 4, index: 54 }; // RNM(path-rootless)
    this.rules[50].opcodes[7] = { type: 4, index: 55 }; // RNM(path-empty)

    /* authority */
    this.rules[51].opcodes = [];
    this.rules[51].opcodes[0] = { type: 2, children: [1, 3, 4] }; // CAT
    this.rules[51].opcodes[1] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[51].opcodes[2] = { type: 4, index: 56 }; // RNM(userinfo-at)
    this.rules[51].opcodes[3] = { type: 4, index: 58 }; // RNM(host)
    this.rules[51].opcodes[4] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[51].opcodes[5] = { type: 2, children: [6, 7] }; // CAT
    this.rules[51].opcodes[6] = { type: 6, string: [58] }; // TBS
    this.rules[51].opcodes[7] = { type: 4, index: 73 }; // RNM(port)

    /* path-abempty */
    this.rules[52].opcodes = [];
    this.rules[52].opcodes[0] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[52].opcodes[1] = { type: 2, children: [2, 3] }; // CAT
    this.rules[52].opcodes[2] = { type: 6, string: [47] }; // TBS
    this.rules[52].opcodes[3] = { type: 4, index: 76 }; // RNM(segment)

    /* path-absolute */
    this.rules[53].opcodes = [];
    this.rules[53].opcodes[0] = { type: 2, children: [1, 2] }; // CAT
    this.rules[53].opcodes[1] = { type: 6, string: [47] }; // TBS
    this.rules[53].opcodes[2] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[53].opcodes[3] = { type: 2, children: [4, 5] }; // CAT
    this.rules[53].opcodes[4] = { type: 4, index: 77 }; // RNM(segment-nz)
    this.rules[53].opcodes[5] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[53].opcodes[6] = { type: 2, children: [7, 8] }; // CAT
    this.rules[53].opcodes[7] = { type: 6, string: [47] }; // TBS
    this.rules[53].opcodes[8] = { type: 4, index: 76 }; // RNM(segment)

    /* path-rootless */
    this.rules[54].opcodes = [];
    this.rules[54].opcodes[0] = { type: 2, children: [1, 2] }; // CAT
    this.rules[54].opcodes[1] = { type: 4, index: 77 }; // RNM(segment-nz)
    this.rules[54].opcodes[2] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[54].opcodes[3] = { type: 2, children: [4, 5] }; // CAT
    this.rules[54].opcodes[4] = { type: 6, string: [47] }; // TBS
    this.rules[54].opcodes[5] = { type: 4, index: 76 }; // RNM(segment)

    /* path-empty */
    this.rules[55].opcodes = [];
    this.rules[55].opcodes[0] = { type: 7, string: [] }; // TLS

    /* userinfo-at */
    this.rules[56].opcodes = [];
    this.rules[56].opcodes[0] = { type: 2, children: [1, 2] }; // CAT
    this.rules[56].opcodes[1] = { type: 4, index: 57 }; // RNM(userinfo)
    this.rules[56].opcodes[2] = { type: 6, string: [64] }; // TBS

    /* userinfo */
    this.rules[57].opcodes = [];
    this.rules[57].opcodes[0] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[57].opcodes[1] = { type: 1, children: [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] }; // ALT
    this.rules[57].opcodes[2] = { type: 5, min: 97, max: 122 }; // TRG
    this.rules[57].opcodes[3] = { type: 5, min: 65, max: 90 }; // TRG
    this.rules[57].opcodes[4] = { type: 5, min: 48, max: 57 }; // TRG
    this.rules[57].opcodes[5] = { type: 4, index: 80 }; // RNM(pct-encoded)
    this.rules[57].opcodes[6] = { type: 6, string: [33] }; // TBS
    this.rules[57].opcodes[7] = { type: 6, string: [36] }; // TBS
    this.rules[57].opcodes[8] = { type: 5, min: 38, max: 46 }; // TRG
    this.rules[57].opcodes[9] = { type: 5, min: 58, max: 59 }; // TRG
    this.rules[57].opcodes[10] = { type: 6, string: [61] }; // TBS
    this.rules[57].opcodes[11] = { type: 6, string: [95] }; // TBS
    this.rules[57].opcodes[12] = { type: 6, string: [126] }; // TBS

    /* host */
    this.rules[58].opcodes = [];
    this.rules[58].opcodes[0] = { type: 1, children: [1, 2, 6] }; // ALT
    this.rules[58].opcodes[1] = { type: 4, index: 59 }; // RNM(IP-literal)
    this.rules[58].opcodes[2] = { type: 2, children: [3, 4] }; // CAT
    this.rules[58].opcodes[3] = { type: 4, index: 68 }; // RNM(IPv4address)
    this.rules[58].opcodes[4] = { type: 13 }; // NOT
    this.rules[58].opcodes[5] = { type: 4, index: 72 }; // RNM(reg-name-char)
    this.rules[58].opcodes[6] = { type: 4, index: 71 }; // RNM(reg-name)

    /* IP-literal */
    this.rules[59].opcodes = [];
    this.rules[59].opcodes[0] = { type: 2, children: [1, 2, 5] }; // CAT
    this.rules[59].opcodes[1] = { type: 6, string: [91] }; // TBS
    this.rules[59].opcodes[2] = { type: 1, children: [3, 4] }; // ALT
    this.rules[59].opcodes[3] = { type: 4, index: 61 }; // RNM(IPv6address)
    this.rules[59].opcodes[4] = { type: 4, index: 60 }; // RNM(IPvFuture)
    this.rules[59].opcodes[5] = { type: 6, string: [93] }; // TBS

    /* IPvFuture */
    this.rules[60].opcodes = [];
    this.rules[60].opcodes[0] = { type: 2, children: [1, 2, 7, 8] }; // CAT
    this.rules[60].opcodes[1] = { type: 7, string: [118] }; // TLS
    this.rules[60].opcodes[2] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[60].opcodes[3] = { type: 1, children: [4, 5, 6] }; // ALT
    this.rules[60].opcodes[4] = { type: 5, min: 48, max: 57 }; // TRG
    this.rules[60].opcodes[5] = { type: 5, min: 65, max: 70 }; // TRG
    this.rules[60].opcodes[6] = { type: 5, min: 97, max: 102 }; // TRG
    this.rules[60].opcodes[7] = { type: 7, string: [46] }; // TLS
    this.rules[60].opcodes[8] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[60].opcodes[9] = { type: 1, children: [10, 11, 12, 13, 14, 15, 16, 17, 18, 19] }; // ALT
    this.rules[60].opcodes[10] = { type: 5, min: 97, max: 122 }; // TRG
    this.rules[60].opcodes[11] = { type: 5, min: 65, max: 90 }; // TRG
    this.rules[60].opcodes[12] = { type: 5, min: 48, max: 57 }; // TRG
    this.rules[60].opcodes[13] = { type: 6, string: [33] }; // TBS
    this.rules[60].opcodes[14] = { type: 6, string: [36] }; // TBS
    this.rules[60].opcodes[15] = { type: 5, min: 38, max: 46 }; // TRG
    this.rules[60].opcodes[16] = { type: 5, min: 58, max: 59 }; // TRG
    this.rules[60].opcodes[17] = { type: 6, string: [61] }; // TBS
    this.rules[60].opcodes[18] = { type: 6, string: [95] }; // TBS
    this.rules[60].opcodes[19] = { type: 6, string: [126] }; // TBS

    /* IPv6address */
    this.rules[61].opcodes = [];
    this.rules[61].opcodes[0] = { type: 1, children: [1, 2] }; // ALT
    this.rules[61].opcodes[1] = { type: 4, index: 62 }; // RNM(nodcolon)
    this.rules[61].opcodes[2] = { type: 4, index: 63 }; // RNM(dcolon)

    /* nodcolon */
    this.rules[62].opcodes = [];
    this.rules[62].opcodes[0] = { type: 2, children: [1, 5] }; // CAT
    this.rules[62].opcodes[1] = { type: 2, children: [2, 3] }; // CAT
    this.rules[62].opcodes[2] = { type: 4, index: 66 }; // RNM(h16n)
    this.rules[62].opcodes[3] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[62].opcodes[4] = { type: 4, index: 67 }; // RNM(h16cn)
    this.rules[62].opcodes[5] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[62].opcodes[6] = { type: 2, children: [7, 8] }; // CAT
    this.rules[62].opcodes[7] = { type: 6, string: [58] }; // TBS
    this.rules[62].opcodes[8] = { type: 4, index: 68 }; // RNM(IPv4address)

    /* dcolon */
    this.rules[63].opcodes = [];
    this.rules[63].opcodes[0] = { type: 2, children: [1, 6, 7] }; // CAT
    this.rules[63].opcodes[1] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[63].opcodes[2] = { type: 2, children: [3, 4] }; // CAT
    this.rules[63].opcodes[3] = { type: 4, index: 64 }; // RNM(h16)
    this.rules[63].opcodes[4] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[63].opcodes[5] = { type: 4, index: 65 }; // RNM(h16c)
    this.rules[63].opcodes[6] = { type: 6, string: [58, 58] }; // TBS
    this.rules[63].opcodes[7] = { type: 1, children: [8, 17] }; // ALT
    this.rules[63].opcodes[8] = { type: 2, children: [9, 13] }; // CAT
    this.rules[63].opcodes[9] = { type: 2, children: [10, 11] }; // CAT
    this.rules[63].opcodes[10] = { type: 4, index: 66 }; // RNM(h16n)
    this.rules[63].opcodes[11] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[63].opcodes[12] = { type: 4, index: 67 }; // RNM(h16cn)
    this.rules[63].opcodes[13] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[63].opcodes[14] = { type: 2, children: [15, 16] }; // CAT
    this.rules[63].opcodes[15] = { type: 6, string: [58] }; // TBS
    this.rules[63].opcodes[16] = { type: 4, index: 68 }; // RNM(IPv4address)
    this.rules[63].opcodes[17] = { type: 3, min: 0, max: 1 }; // REP
    this.rules[63].opcodes[18] = { type: 4, index: 68 }; // RNM(IPv4address)

    /* h16 */
    this.rules[64].opcodes = [];
    this.rules[64].opcodes[0] = { type: 3, min: 1, max: 4 }; // REP
    this.rules[64].opcodes[1] = { type: 1, children: [2, 3, 4] }; // ALT
    this.rules[64].opcodes[2] = { type: 5, min: 48, max: 57 }; // TRG
    this.rules[64].opcodes[3] = { type: 5, min: 65, max: 70 }; // TRG
    this.rules[64].opcodes[4] = { type: 5, min: 97, max: 102 }; // TRG

    /* h16c */
    this.rules[65].opcodes = [];
    this.rules[65].opcodes[0] = { type: 2, children: [1, 2] }; // CAT
    this.rules[65].opcodes[1] = { type: 6, string: [58] }; // TBS
    this.rules[65].opcodes[2] = { type: 3, min: 1, max: 4 }; // REP
    this.rules[65].opcodes[3] = { type: 1, children: [4, 5, 6] }; // ALT
    this.rules[65].opcodes[4] = { type: 5, min: 48, max: 57 }; // TRG
    this.rules[65].opcodes[5] = { type: 5, min: 65, max: 70 }; // TRG
    this.rules[65].opcodes[6] = { type: 5, min: 97, max: 102 }; // TRG

    /* h16n */
    this.rules[66].opcodes = [];
    this.rules[66].opcodes[0] = { type: 2, children: [1, 6] }; // CAT
    this.rules[66].opcodes[1] = { type: 3, min: 1, max: 4 }; // REP
    this.rules[66].opcodes[2] = { type: 1, children: [3, 4, 5] }; // ALT
    this.rules[66].opcodes[3] = { type: 5, min: 48, max: 57 }; // TRG
    this.rules[66].opcodes[4] = { type: 5, min: 65, max: 70 }; // TRG
    this.rules[66].opcodes[5] = { type: 5, min: 97, max: 102 }; // TRG
    this.rules[66].opcodes[6] = { type: 13 }; // NOT
    this.rules[66].opcodes[7] = { type: 6, string: [46] }; // TBS

    /* h16cn */
    this.rules[67].opcodes = [];
    this.rules[67].opcodes[0] = { type: 2, children: [1, 2, 7] }; // CAT
    this.rules[67].opcodes[1] = { type: 6, string: [58] }; // TBS
    this.rules[67].opcodes[2] = { type: 3, min: 1, max: 4 }; // REP
    this.rules[67].opcodes[3] = { type: 1, children: [4, 5, 6] }; // ALT
    this.rules[67].opcodes[4] = { type: 5, min: 48, max: 57 }; // TRG
    this.rules[67].opcodes[5] = { type: 5, min: 65, max: 70 }; // TRG
    this.rules[67].opcodes[6] = { type: 5, min: 97, max: 102 }; // TRG
    this.rules[67].opcodes[7] = { type: 13 }; // NOT
    this.rules[67].opcodes[8] = { type: 6, string: [46] }; // TBS

    /* IPv4address */
    this.rules[68].opcodes = [];
    this.rules[68].opcodes[0] = { type: 2, children: [1, 2, 3, 4, 5, 6, 7] }; // CAT
    this.rules[68].opcodes[1] = { type: 4, index: 69 }; // RNM(dec-octet)
    this.rules[68].opcodes[2] = { type: 6, string: [46] }; // TBS
    this.rules[68].opcodes[3] = { type: 4, index: 69 }; // RNM(dec-octet)
    this.rules[68].opcodes[4] = { type: 6, string: [46] }; // TBS
    this.rules[68].opcodes[5] = { type: 4, index: 69 }; // RNM(dec-octet)
    this.rules[68].opcodes[6] = { type: 6, string: [46] }; // TBS
    this.rules[68].opcodes[7] = { type: 4, index: 69 }; // RNM(dec-octet)

    /* dec-octet */
    this.rules[69].opcodes = [];
    this.rules[69].opcodes[0] = { type: 3, min: 0, max: 3 }; // REP
    this.rules[69].opcodes[1] = { type: 4, index: 70 }; // RNM(dec-digit)

    /* dec-digit */
    this.rules[70].opcodes = [];
    this.rules[70].opcodes[0] = { type: 5, min: 48, max: 57 }; // TRG

    /* reg-name */
    this.rules[71].opcodes = [];
    this.rules[71].opcodes[0] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[71].opcodes[1] = { type: 4, index: 72 }; // RNM(reg-name-char)

    /* reg-name-char */
    this.rules[72].opcodes = [];
    this.rules[72].opcodes[0] = { type: 1, children: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] }; // ALT
    this.rules[72].opcodes[1] = { type: 5, min: 97, max: 122 }; // TRG
    this.rules[72].opcodes[2] = { type: 5, min: 65, max: 90 }; // TRG
    this.rules[72].opcodes[3] = { type: 5, min: 48, max: 57 }; // TRG
    this.rules[72].opcodes[4] = { type: 4, index: 80 }; // RNM(pct-encoded)
    this.rules[72].opcodes[5] = { type: 6, string: [33] }; // TBS
    this.rules[72].opcodes[6] = { type: 6, string: [36] }; // TBS
    this.rules[72].opcodes[7] = { type: 5, min: 38, max: 46 }; // TRG
    this.rules[72].opcodes[8] = { type: 6, string: [59] }; // TBS
    this.rules[72].opcodes[9] = { type: 6, string: [61] }; // TBS
    this.rules[72].opcodes[10] = { type: 6, string: [95] }; // TBS
    this.rules[72].opcodes[11] = { type: 6, string: [126] }; // TBS

    /* port */
    this.rules[73].opcodes = [];
    this.rules[73].opcodes[0] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[73].opcodes[1] = { type: 5, min: 48, max: 57 }; // TRG

    /* query */
    this.rules[74].opcodes = [];
    this.rules[74].opcodes[0] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[74].opcodes[1] = { type: 1, children: [2, 3, 4] }; // ALT
    this.rules[74].opcodes[2] = { type: 4, index: 79 }; // RNM(pchar)
    this.rules[74].opcodes[3] = { type: 6, string: [47] }; // TBS
    this.rules[74].opcodes[4] = { type: 6, string: [63] }; // TBS

    /* fragment */
    this.rules[75].opcodes = [];
    this.rules[75].opcodes[0] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[75].opcodes[1] = { type: 1, children: [2, 3, 4] }; // ALT
    this.rules[75].opcodes[2] = { type: 4, index: 79 }; // RNM(pchar)
    this.rules[75].opcodes[3] = { type: 6, string: [47] }; // TBS
    this.rules[75].opcodes[4] = { type: 6, string: [63] }; // TBS

    /* segment */
    this.rules[76].opcodes = [];
    this.rules[76].opcodes[0] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[76].opcodes[1] = { type: 4, index: 79 }; // RNM(pchar)

    /* segment-nz */
    this.rules[77].opcodes = [];
    this.rules[77].opcodes[0] = { type: 3, min: 1, max: Infinity }; // REP
    this.rules[77].opcodes[1] = { type: 4, index: 79 }; // RNM(pchar)

    /* scheme */
    this.rules[78].opcodes = [];
    this.rules[78].opcodes[0] = { type: 2, children: [1, 4] }; // CAT
    this.rules[78].opcodes[1] = { type: 1, children: [2, 3] }; // ALT
    this.rules[78].opcodes[2] = { type: 5, min: 97, max: 122 }; // TRG
    this.rules[78].opcodes[3] = { type: 5, min: 65, max: 90 }; // TRG
    this.rules[78].opcodes[4] = { type: 3, min: 0, max: Infinity }; // REP
    this.rules[78].opcodes[5] = { type: 1, children: [6, 9, 10, 11] }; // ALT
    this.rules[78].opcodes[6] = { type: 1, children: [7, 8] }; // ALT
    this.rules[78].opcodes[7] = { type: 5, min: 97, max: 122 }; // TRG
    this.rules[78].opcodes[8] = { type: 5, min: 65, max: 90 }; // TRG
    this.rules[78].opcodes[9] = { type: 5, min: 48, max: 57 }; // TRG
    this.rules[78].opcodes[10] = { type: 6, string: [43] }; // TBS
    this.rules[78].opcodes[11] = { type: 5, min: 45, max: 46 }; // TRG

    /* pchar */
    this.rules[79].opcodes = [];
    this.rules[79].opcodes[0] = { type: 1, children: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] }; // ALT
    this.rules[79].opcodes[1] = { type: 5, min: 97, max: 122 }; // TRG
    this.rules[79].opcodes[2] = { type: 5, min: 64, max: 90 }; // TRG
    this.rules[79].opcodes[3] = { type: 5, min: 48, max: 59 }; // TRG
    this.rules[79].opcodes[4] = { type: 6, string: [33] }; // TBS
    this.rules[79].opcodes[5] = { type: 6, string: [36] }; // TBS
    this.rules[79].opcodes[6] = { type: 5, min: 38, max: 46 }; // TRG
    this.rules[79].opcodes[7] = { type: 6, string: [61] }; // TBS
    this.rules[79].opcodes[8] = { type: 6, string: [95] }; // TBS
    this.rules[79].opcodes[9] = { type: 6, string: [126] }; // TBS
    this.rules[79].opcodes[10] = { type: 4, index: 80 }; // RNM(pct-encoded)

    /* pct-encoded */
    this.rules[80].opcodes = [];
    this.rules[80].opcodes[0] = { type: 2, children: [1, 2, 6] }; // CAT
    this.rules[80].opcodes[1] = { type: 6, string: [37] }; // TBS
    this.rules[80].opcodes[2] = { type: 1, children: [3, 4, 5] }; // ALT
    this.rules[80].opcodes[3] = { type: 5, min: 48, max: 57 }; // TRG
    this.rules[80].opcodes[4] = { type: 5, min: 65, max: 70 }; // TRG
    this.rules[80].opcodes[5] = { type: 5, min: 97, max: 102 }; // TRG
    this.rules[80].opcodes[6] = { type: 1, children: [7, 8, 9] }; // ALT
    this.rules[80].opcodes[7] = { type: 5, min: 48, max: 57 }; // TRG
    this.rules[80].opcodes[8] = { type: 5, min: 65, max: 70 }; // TRG
    this.rules[80].opcodes[9] = { type: 5, min: 97, max: 102 }; // TRG

    /* unreserved */
    this.rules[81].opcodes = [];
    this.rules[81].opcodes[0] = { type: 1, children: [1, 2, 3, 4, 5, 6] }; // ALT
    this.rules[81].opcodes[1] = { type: 5, min: 97, max: 122 }; // TRG
    this.rules[81].opcodes[2] = { type: 5, min: 65, max: 90 }; // TRG
    this.rules[81].opcodes[3] = { type: 5, min: 48, max: 57 }; // TRG
    this.rules[81].opcodes[4] = { type: 5, min: 45, max: 46 }; // TRG
    this.rules[81].opcodes[5] = { type: 6, string: [95] }; // TBS
    this.rules[81].opcodes[6] = { type: 6, string: [126] }; // TBS

    /* reserved */
    this.rules[82].opcodes = [];
    this.rules[82].opcodes[0] = { type: 1, children: [1, 2, 3, 4, 5, 6, 7, 8, 9] }; // ALT
    this.rules[82].opcodes[1] = { type: 6, string: [33] }; // TBS
    this.rules[82].opcodes[2] = { type: 5, min: 35, max: 36 }; // TRG
    this.rules[82].opcodes[3] = { type: 5, min: 38, max: 44 }; // TRG
    this.rules[82].opcodes[4] = { type: 6, string: [47] }; // TBS
    this.rules[82].opcodes[5] = { type: 5, min: 58, max: 59 }; // TRG
    this.rules[82].opcodes[6] = { type: 6, string: [61] }; // TBS
    this.rules[82].opcodes[7] = { type: 5, min: 63, max: 64 }; // TRG
    this.rules[82].opcodes[8] = { type: 6, string: [91] }; // TBS
    this.rules[82].opcodes[9] = { type: 6, string: [93] }; // TBS

    // The `toString()` function will display the original grammar file(s) that produced these opcodes.
    this.toString = function toString() {
      let str = '';
      str += ';\n';
      str += '; LDT 12/15/2024 \n';
      str +=
        '; The ERC-4361 (https://eips.ethereum.org/EIPS/eip-4361) ABNF format has been modified in several significant ways.\n';
      str += '; 1) Literal strings are replaced with numbers and ranges (%d32 & %d32-126, etc.) when possible.\n';
      str += ';    TRB and especially TRG operators are much more efficient than TLS operators.\n';
      str += '; 2) The message items (scheme, etc.) are first defined as general strings of any characters.\n';
      str += ';    On a second pass, these item are validated against the ERC_4361 format individually.\n';
      str +=
        '; 3) IPv6address does not work because of APG\'s "first-success disambiguation" and "greedy" repetitions.\n';
      str +=
        ';    IPv6address is redefined and validations moved to callback functions (semantic vs syntactic validation).\n';
      str +=
        ';    Redefinition requires negative look-ahead operators, https://en.wikipedia.org/wiki/Syntactic_predicate.\n';
      str += ';    That is, SABNF instead of simple ABNF.\n';
      str += '; 4) IPv4address fails because of "first-success disambiguation".\n';
      str += ';    This could be fixed with rearrangement of the alternative terms.\n';
      str += ';    However, it would still not accept zero-padded (leading zeros) decimal octets.\n';
      str += ';    Therefore, IPv4address is also done with callback functions and semantic validation.\n';
      str += '; 5) The negative look-ahead operator is also needed in the definition of host to\n';
      str += ';    prevent failure with a reg-name that begins with an IPv4 address.\n';
      str += '; 6) NOTE: host = 1.1.1.256 is a valid host name even though it is an invalid IPv4address.\n';
      str += ';          The IPv4address alternative fails but the reg-name alternative succeeds.\n';
      str += '; 7) The ERC-4361 message format ABNF allows for empty statements.\n';
      str += ';    Because of the "first success disambiguation" of APG\n';
      str += ';    the an explicit "empty-statement" rule is required to match the spec\'s intent.\n';
      str +=
        '; 8) Basics LF, ALPHA, DIGIT and HEXDIG have been expanded in place to reduce the number of rule name operations.\n';
      str += ';\n';
      str += 'siwe-first-pass =\n';
      str += '    [ ffscheme ] fdomain %s" wants you to sign in with your Ethereum account:" %d10\n';
      str += '    faddress %d10\n';
      str += '    (empty-statement / no-statement / actual-statement)\n';
      str += '    pre-uri furi %d10\n';
      str += '    pre-version fversion %d10\n';
      str += '    pre-chain-id fchain-id %d10\n';
      str += '    pre-nonce fnonce %d10\n';
      str += '    pre-issued-at fissued-at\n';
      str += '    [ %d10 %s"Expiration Time: " fexpiration-time ]\n';
      str += '    [ %d10 %s"Not Before: " fnot-before ]\n';
      str += '    [ %d10 %s"Request ID: " frequest-id ]\n';
      str += '    [ %d10 %s"Resources:" fresources]\n';
      str += '\n';
      str += 'pre-uri = %s"URI: "\n';
      str += 'pre-version       = %s"Version: "\n';
      str += 'pre-chain-id      = %s"Chain ID: "\n';
      str += 'pre-nonce         = %s"Nonce: "\n';
      str += 'pre-issued-at     = %s"Issued At: "\n';
      str += 'ffscheme          = fscheme %s"://"\n';
      str += 'fdomain           = 1*(%d0-31 / %d33-127) ; all characters but space\n';
      str += 'fissued-at        = 1*(%d0-9 / %d11-127)  ; all characters but linefeed\n';
      str += 'fexpiration-time  = 1*(%d0-9 / %d11-127)\n';
      str += 'fnot-before       = 1*(%d0-9 / %d11-127)\n';
      str += 'furi              = 1*(%d0-9 / %d11-127)\n';
      str += 'fscheme           = 1*(%d0-57 / %d59-127) ; any character but colon(:)\n';
      str += 'faddress          = 1*(%d0-9 / %d11-127)\n';
      str += 'fstatement        = 1*(%d0-9 / %d11-127)\n';
      str += 'fversion          = 1*(%d0-9 / %d11-127)\n';
      str += 'fchain-id         = 1*(%d0-9 / %d11-127)\n';
      str += 'fnonce            = 1*(%d0-9 / %d11-127)\n';
      str += 'frequest-id       = *(%d0-9 / %d11-127)\n';
      str += 'fresources        = *( %d10 fresource )\n';
      str += 'fresource         = "- " 1*(%d0-9 / %d11-127)\n';
      str += 'no-statement      = %d10.10\n';
      str += 'empty-statement   = %d10.10.10\n';
      str += 'actual-statement  = %d10 fstatement %d10.10\n';
      str += '\n';
      str += 'domain = authority\n';
      str += '    ; From RFC 3986:\n';
      str += 'address = %s"0x" 40*40(%d48-57 / %d65-70 / %d97-102)\n';
      str += '    ; Optionally must also conform to capitalization\n';
      str += '    ; checksum encoding specified in EIP-55\n';
      str += 'statement = 1*( reserved / unreserved / " " )\n';
      str += '    ; See RFC 3986 for the definition\n';
      str += '    ; of "reserved" and "unreserved".\n';
      str += '    ; The purpose is to exclude %d10 (line break).\n';
      str += 'version = %s"1"\n';
      str += 'chain-id = 1*%d48-57\n';
      str += '    ; See EIP-155 for valid CHAIN_IDs.\n';
      str += 'nonce = 8*( (%d97-122 / %d65-90) / %d48-57 )\n';
      str += 'issued-at = date-time\n';
      str += 'expiration-time = date-time\n';
      str += 'not-before = date-time\n';
      str += '    ; See RFC 3339 (ISO 8601) for the\n';
      str += '    ; definition of "date-time".\n';
      str += 'request-id = *pchar\n';
      str += '    ; See RFC 3986 for the definition of "pchar".\n';
      str += 'resources = *( %d10 resource )\n';
      str += 'resource = %s"- " URI\n';
      str += '\n';
      str += '; RFC 3339 - Date and Time on the Internet: Timestamps\n';
      str += 'date-fullyear   = 4%d48-57\n';
      str += 'date-month      = 2%d48-57  ; 01-12\n';
      str += 'date-mday       = 2%d48-57  ; 01-28, 01-29, 01-30, 01-31 based on\n';
      str += '                            ; month/year\n';
      str += 'time-hour       = 2%d48-57  ; 00-23\n';
      str += 'time-minute     = 2%d48-57  ; 00-59\n';
      str += 'time-second     = 2%d48-57  ; 00-58, 00-59, 00-60 based on leap second\n';
      str += '                            ; rules\n';
      str += 'time-secfrac    = %s"." 1*%d48-57\n';
      str += 'time-numoffset  = (%s"+" / %s"-") time-hour %s":" time-minute\n';
      str += 'time-offset     = "Z" / time-numoffset\n';
      str += 'partial-time    = time-hour %s":" time-minute %s":" time-second\n';
      str += '                  [time-secfrac]\n';
      str += 'full-date       = date-fullyear %s"-" date-month %s"-" date-mday\n';
      str += 'full-time       = partial-time time-offset\n';
      str += 'date-time       = full-date "T" full-time\n';
      str += '\n';
      str += '; RFC 3986 - Uniform Resource Identifier (URI): Generic Syntax\n';
      str += '; Modified to improve APG parsing and callback functions.\n';
      str += 'URI           = scheme %s":" hier-part [ %s"?" query ] [ %s"#" fragment ]\n';
      str += 'hier-part     = %s"//" authority path-abempty\n';
      str += '              / path-absolute\n';
      str += '              / path-rootless\n';
      str += '              / path-empty\n';
      str += 'authority     = [ userinfo-at ] host [ %s":" port ]\n';
      str += 'path-abempty  = *( %s"/" segment )\n';
      str += 'path-absolute = %s"/" [ segment-nz *( %s"/" segment ) ]\n';
      str += 'path-rootless = segment-nz *( %s"/" segment )\n';
      str += 'path-empty    = ""\n';
      str += 'userinfo-at   = userinfo %d64\n';
      str += '                ; userinfo redefined to include the "@" so that it will fail without it\n';
      str += '                ; otherwise userinfo can match host and then the parser will backtrack\n';
      str += '                ; incorrectly keeping the captured userinfo phrase\n';
      str +=
        'userinfo      = *(%d97-122 / %d65-90 / %d48-57 / pct-encoded / %d33 / %d36 / %d38-46 / %d58-59 / %d61 / %d95 / %d126)\n';
      str += 'host          = IP-literal / (IPv4address !reg-name-char) / reg-name\n';
      str +=
        '                ; negative look-ahead required to prevent IPv4address from being recognized as first part of reg-name\n';
      str += '                ; same fix as https://github.com/garycourt/uri-js/issues/4\n';
      str += 'IP-literal    = %s"[" ( IPv6address / IPvFuture  ) %s"]"\n';
      str +=
        'IPvFuture     = "v" 1*(%d48-57 / %d65-70 / %d97-102) "." 1*( %d97-122 / %d65-90 / %d48-57 / %d33 / %d36 /%d38-46 / %d58-59 /%d61 /%d95 / %d126 )\n';
      str += 'IPv6address   = nodcolon / dcolon\n';
      str += 'nodcolon      = (h16n *h16cn) [%d58 IPv4address]\n';
      str += 'dcolon        = [h16 *h16c] %d58.58 (((h16n *h16cn) [%d58 IPv4address]) / [IPv4address])\n';
      str += 'h16           = 1*4(%d48-57 / %d65-70 / %d97-102)\n';
      str += 'h16c          = %d58 1*4(%d48-57 / %d65-70 / %d97-102)\n';
      str += 'h16n          = 1*4(%d48-57 / %d65-70 / %d97-102) !%d46\n';
      str += 'h16cn         = %d58 1*4(%d48-57 / %d65-70 / %d97-102) !%d46\n';
      str += 'IPv4address   = dec-octet %s"." dec-octet %s"." dec-octet %s"." dec-octet\n';
      str +=
        '; Here we will will use callback functions to evaluate and validate the (possibly zero-padded) dec-octet.\n';
      str += 'dec-octet     =  *3dec-digit\n';
      str += 'dec-digit     = %d48-57\n';
      str += 'reg-name      = *reg-name-char\n';
      str +=
        'reg-name-char = %d97-122 / %d65-90 / %d48-57 / pct-encoded / %d33 / %d36 / %d38-46 / %d59 / %d61 /%d95 / %d126\n';
      str += 'port          = *%d48-57\n';
      str += 'query         = *(pchar / %d47 / %d63)\n';
      str += 'fragment      = *(pchar / %d47 / %d63)\n';
      str += 'segment       = *pchar\n';
      str += 'segment-nz    = 1*pchar\n';
      str += 'scheme        = (%d97-122 / %d65-90) *( (%d97-122 / %d65-90) / %d48-57 / %d43 / %d45-46)\n';
      str +=
        'pchar         = %d97-122 / %d64-90 /  %d48-59 / %d33 / %d36 / %d38-46 / %d61 / %d95 / %d126 / pct-encoded\n';
      str += 'pct-encoded   = %s"%" (%d48-57 / %d65-70 / %d97-102) (%d48-57 / %d65-70 / %d97-102)\n';
      str += 'unreserved    = %d97-122 / %d65-90 /  %d48-57 / %d45-46 / %d95 / %d126\n';
      str += 'reserved      = %d33 / %d35-36 / %d38-44 / %d47 / %d58-59 / %d61 / %d63-64 / %d91 / %d93\n';
      str += ';scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )\n';
      str += ';pchar         = unreserved / pct-encoded / sub-delims / %s":" / %s"@"\n';
      str += ';unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"\n';
      str += ';reserved      = gen-delims / sub-delims\n';
      str += ';gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"\n';
      str += ';gen-delims    = %d35 / %d47 / %d58 /%d63-64 / %d91 / %d93\n';
      str += ';sub-delims    = "!" / "$" / "&" / "\'" / "(" / ")"\n';
      str += ';                 / "*" / "+" / "," / ";" / "="\n';
      str += ';sub-delims    = %d33 / %d36 / %d38-44 / %d59 / %d61\n';
      str += '\n';
      return str;
    };
  }

  const cb = {
    ffscheme: function ffscheme(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.fscheme = utilities.charsToString(chars, phraseIndex, sysData.phraseLength).slice(0, -3);
      }
    },
    fdomain: function fdomain(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.fdomain = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
      }
    },
    faddress: function faddress(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.faddress = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
      }
    },
    authority: function authority(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.authority = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
      }
    },
    fstatement: function fstatement(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.fstatement = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
      }
    },
    preUri: function preUri(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.NOMATCH || sysData.state === identifiers.EMPTY) {
        data.error = 'URI missing or invalid prefix "URI: "';
      }
    },
    furi: function furi(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.furi = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
      }
    },
    preVersion: function preVersion(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.NOMATCH || sysData.state === identifiers.EMPTY) {
        data.error = 'Version missing or invalid prefix "Version: "';
      }
    },
    fversion: function fversion(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.fversion = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
      }
    },
    preChainId: function preChainId(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.NOMATCH || sysData.state === identifiers.EMPTY) {
        data.error = 'Chain ID missing or invalid prefex "Chain ID: "';
      }
    },
    fchainId: function fchainId(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.fchainId = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
      }
    },
    preNonce: function preNonce(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.NOMATCH || sysData.state === identifiers.EMPTY) {
        data.error = 'Nonce missing or invalid Nonce prefex "Nonce: "';
      }
    },
    fnonce: function fnonce(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.fnonce = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
      }
    },
    preIssuedAt: function preIssuedAt(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.NOMATCH || sysData.state === identifiers.EMPTY) {
        data.error = 'Issued At missing or invalid Issued At prefex "Issued At: "';
      }
    },
    fissuedAt: function fissuedAt(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.fissuedAt = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
      }
    },
    fexpirationTime: function fexpirationTime(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.fexpirationTime = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
      }
    },
    fnotBefore: function fnotBefore(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.fnotBefore = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
      }
    },
    frequestId: function frequestId(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.frequestId = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
      } else if (sysData.state === identifiers.EMPTY) {
        data.frequestId = '';
      }
    },
    fresources: function fresources(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.ACTIVE) {
        data.fresources = [];
      }
    },
    fresource: function fresource(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.fresources.push(utilities.charsToString(chars, phraseIndex, sysData.phraseLength).slice(2));
      }
    },
    emptyStatement: function emptyStatement(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.fstatement = '';
      }
    },
    noStatement: function noStatement(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.fstatement = undefined;
      }
    },
    actualStatement: function actualStatement(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.fstatement = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
      }
    },
    // handle the URI
    URI: function URI(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.ACTIVE:
          data.errorslength = 0;
          break;
        case identifiers.MATCH:
          data.uri = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
          break;
        case identifiers.EMPTY:
          sysData.state = identifiers.NOMATCH;
          sysData.phraseLength = 0;
          break;
      }
    },
    scheme: function scheme(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.MATCH:
          data.scheme = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
          break;
      }
    },
    userinfo: function userinfo(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.MATCH:
          data.userinfo = utilities.charsToString(chars, phraseIndex, sysData.phraseLength - 1);
          break;
      }
    },
    host: function host(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.ACTIVE:
          data.iplit = false;
          break;
        case identifiers.MATCH:
          if (data.iplit) {
            // strip leading "[" and trailing "]" brackets
            data.host = utilities.charsToString(chars, phraseIndex + 1, sysData.phraseLength - 2);
          } else {
            data.host = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
          }
          break;
        case identifiers.EMPTY:
          data.host = '';
          break;
      }
    },
    ipLiteral: function ipLiteral(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.iplit = true;
      }
    },
    port: function port(sysData, chars, phraseIndex, data) {
      let parsed = 0;
      let port = '';
      switch (sysData.state) {
        case identifiers.MATCH:
          port = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
          parsed = parseInt(port);
          if (Number.isNaN(parsed)) {
            sysData.state = identifiers.NOMATCH;
            sysData.phraseLength = 0;
          } else {
            data.port = parsed;
          }
          break;
        case identifiers.EMPTY:
          data.port = '';
          break;
      }
    },
    pathAbempty: function pathAbempty(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.MATCH:
          data.path = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
          break;
        case identifiers.EMPTY:
          data.path = '';
          break;
      }
    },
    pathAbsolute: function pathAbsolute(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.MATCH:
          data.path = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
          break;
      }
    },
    pathRootless: function pathRootless(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.MATCH:
          data.path = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
          break;
      }
    },
    pathEmpty: function pathEmpty(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.MATCH:
        case identifiers.NOMATCH:
          sysData.state = identifiers.NOMATCH;
          sysData.phraseLength = 0;
        case identifiers.EMPTY:
          data.path = '';
          break;
      }
    },
    query: function query(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.MATCH:
          data.query = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
          break;
        case identifiers.EMPTY:
          data.query = '';
          break;
      }
    },
    fragment: function fragment(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.MATCH:
          data.fragment = utilities.charsToString(chars, phraseIndex, sysData.phraseLength);
          break;
        case identifiers.EMPTY:
          data.fragment = '';
          break;
      }
    },
    ipv4: function ipv4(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.ipv4 = true;
      }
    },
    h16: function h16(sysData, chars, phraseIndex, data) {
      if (sysData.state === identifiers.MATCH) {
        data.h16count += 1;
      }
    },
    nodcolon: function nodcolon(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.ACTIVE:
          data.h16count = 0;
          data.ipv4 = false;
          break;
        case identifiers.MATCH:
          // semantically validate the number of 16-bit digits
          if (data.ipv4) {
            if (data.h16count === 6) {
              sysData.state = identifiers.MATCH;
            } else {
              sysData.state = identifiers.NOMATCH;
              sysData.phraseLength = 0;
            }
          } else {
            if (data.h16count === 8) {
              sysData.state = identifiers.MATCH;
            } else {
              sysData.state = identifiers.NOMATCH;
              sysData.phraseLength = 0;
            }
          }
          break;
      }
    },
    dcolon: function dcolon(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.ACTIVE:
          data.h16count = 0;
          data.ipv4 = false;
          break;
        case identifiers.MATCH:
          // semantically validate the number of 16-bit digits
          if (data.ipv4) {
            if (data.h16count < 6) {
              sysData.state = identifiers.MATCH;
            } else {
              sysData.state = identifiers.NOMATCH;
              sysData.phraseLength = 0;
            }
          } else {
            if (data.h16count < 8) {
              sysData.state = identifiers.MATCH;
            } else {
              sysData.state = identifiers.NOMATCH;
              sysData.phraseLength = 0;
            }
          }
          break;
      }
    },
    decOctet: function decOctet(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.ACTIVE:
          data.octet = 0;
          break;
        case identifiers.MATCH:
          // semantically validate the octet
          if (data.octet > 255) {
            sysData.state = identifiers.NOMATCH;
            sysData.phraseLength = 0;
          }
          break;
      }
    },
    decDigit: function decDigit(sysData, chars, phraseIndex, data) {
      switch (sysData.state) {
        case identifiers.MATCH:
          data.octet = 10 * data.octet + chars[phraseIndex] - 48;
          break;
      }
    },
  };
  /**
   * @file src/keccak256.js
   * @author https://github.com/cryptocoinjs/keccak contributors
   */

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
  function PS() {
    this.parseSiweMessage = parseSiweMessage;
    this.siweObjectToString = siweObjectToString;
    this.isUri = isUri;
    this.keccak256 = keccak256;
    this.isERC55 = isERC55;
    this.toERC55 = toERC55;
    this.noConflict = () => this;
  }
  return new PS();
})();
const _ps = parseSiwe.noConflict();
