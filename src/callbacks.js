import { identifiers, utilities } from './parser.js';

export const cb = {
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
