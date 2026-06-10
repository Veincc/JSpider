import { Buffer } from "node:buffer";
import readline from "node:readline";

import { generate } from "astring";
import { walk } from "estree-walker";
import { parseModule, parseScript } from "meriyah";

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
});

rl.on("line", (line) => {
  if (!line.trim()) {
    return;
  }

  let request;
  try {
    request = JSON.parse(line);
  } catch (_err) {
    write({ id: 0, ok: false, error: "invalid worker request JSON" });
    return;
  }

  if (request.command === "shutdown") {
    process.exit(0);
  }
  if (request.command === "ping") {
    write({
      id: request.id || 0,
      ok: true,
      node_version: process.versions.node,
    });
    return;
  }

  try {
    write(processOne(request));
  } catch (err) {
    write({
      id: request.id || 0,
      ok: false,
      error: String(err && err.message ? err.message : err),
    });
  }
});

function write(value) {
  process.stdout.write(JSON.stringify(value) + "\n");
}

function processOne(request) {
  const source = String(request.source || "");
  const ast = parseJavaScript(source);

  markEscapedStrings(ast);
  decodeLiteralCalls(ast);
  foldStringConcatenations(ast);
  normalizeBracketProperties(ast);
  restoreStringArrayTables(ast);
  decodeLiteralCalls(ast);
  foldStringConcatenations(ast);
  inlineSimpleWrappers(ast);
  decodeLiteralCalls(ast);
  foldStringConcatenations(ast);
  cleanupStaticDeadCode(ast);

  return {
    id: request.id,
    ok: true,
    code: ensureTrailingNewline(generate(ast)),
  };
}

function parseJavaScript(source) {
  const options = {
    next: true,
    loc: true,
    ranges: true,
    raw: true,
    webcompat: true,
  };

  try {
    return parseModule(source, options);
  } catch (moduleErr) {
    try {
      return parseScript(source, { ...options, globalReturn: true });
    } catch (scriptErr) {
      throw new Error(
        "JavaScript parse failed: module parse: "
        + errorMessage(moduleErr)
        + "; script parse: "
        + errorMessage(scriptErr),
      );
    }
  }
}

function errorMessage(err) {
  if (err && err.description) {
    return err.description;
  }
  if (err && err.message) {
    return err.message;
  }
  return String(err);
}

function markEscapedStrings(ast) {
  walk(ast, {
    enter(node) {
      if (
        node.type === "Literal"
        && typeof node.value === "string"
        && typeof node.raw === "string"
        && /\\(?:x[0-9a-fA-F]{2}|u(?:[0-9a-fA-F]{4}|\{[0-9a-fA-F]+\}))/.test(node.raw)
      ) {
        node.raw = JSON.stringify(node.value);
      }
    },
  });
}

function decodeLiteralCalls(ast) {
  walk(ast, {
    leave(node) {
      if (
        node.type !== "CallExpression"
        || node.arguments.length !== 1
        || !isStringLiteral(node.arguments[0])
        || node.callee.type !== "Identifier"
      ) {
        return;
      }

      const value = node.arguments[0].value;
      if (node.callee.name === "atob") {
        const decoded = decodeBase64(value);
        if (decoded !== null) {
          this.replace(literal(decoded));
        }
        return;
      }
      if (node.callee.name === "decodeURIComponent") {
        try {
          this.replace(literal(decodeURIComponent(value)));
        } catch (_err) {
          // Keep malformed URI literals unchanged.
        }
      }
    },
  });
}

function decodeBase64(value) {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 === 1) {
    return null;
  }
  try {
    const decoded = Buffer.from(value, "base64").toString("utf8");
    if (!decoded || decoded.includes("\u0000") || decoded.includes("\uFFFD")) {
      return null;
    }
    return decoded;
  } catch (_err) {
    return null;
  }
}

function foldStringConcatenations(ast) {
  let changed = true;
  while (changed) {
    changed = false;
    walk(ast, {
      leave(node) {
        if (
          node.type === "BinaryExpression"
          && node.operator === "+"
          && isStringLiteral(node.left)
          && isStringLiteral(node.right)
        ) {
          this.replace(literal(node.left.value + node.right.value));
          changed = true;
        }
      },
    });
  }
}

function normalizeBracketProperties(ast) {
  walk(ast, {
    enter(node) {
      if (
        node.type === "MemberExpression"
        && node.computed
        && isStringLiteral(node.property)
        && isIdentifierName(node.property.value)
      ) {
        node.computed = false;
        node.property = identifier(node.property.value);
      }
    },
  });
}

function restoreStringArrayTables(ast) {
  const tables = new Map();
  walk(ast, {
    enter(node) {
      if (
        node.type === "VariableDeclarator"
        && node.id.type === "Identifier"
        && node.init
        && node.init.type === "ArrayExpression"
        && node.init.elements.length > 0
        && node.init.elements.every((element) => isStringLiteral(element))
      ) {
        tables.set(node.id.name, node.init.elements.map((element) => element.value));
      }
    },
  });

  if (tables.size === 0) {
    return;
  }

  walk(ast, {
    leave(node, parent) {
      if (
        node.type !== "MemberExpression"
        || !node.computed
        || node.object.type !== "Identifier"
        || !tables.has(node.object.name)
        || !isIntegerLiteral(node.property)
        || isWriteTarget(node, parent)
      ) {
        return;
      }
      const value = tables.get(node.object.name)[node.property.value];
      if (value !== undefined) {
        this.replace(literal(value));
      }
    },
  });
}

function isWriteTarget(node, parent) {
  if (!parent) {
    return false;
  }
  if (parent.type === "AssignmentExpression" && parent.left === node) {
    return true;
  }
  if (parent.type === "UpdateExpression" && parent.argument === node) {
    return true;
  }
  if (parent.type === "UnaryExpression" && parent.operator === "delete" && parent.argument === node) {
    return true;
  }
  return (
    (parent.type === "ForInStatement" || parent.type === "ForOfStatement")
    && parent.left === node
  );
}

function inlineSimpleWrappers(ast) {
  const wrappers = new Map();
  walk(ast, {
    enter(node) {
      if (node.type === "FunctionDeclaration" && node.id) {
        const wrapper = describeWrapper(node.params, node.body);
        if (wrapper) {
          wrappers.set(node.id.name, wrapper);
        }
        return;
      }
      if (
        node.type === "VariableDeclarator"
        && node.id.type === "Identifier"
        && node.init
        && (node.init.type === "ArrowFunctionExpression" || node.init.type === "FunctionExpression")
      ) {
        const wrapper = describeWrapper(node.init.params, node.init.body);
        if (wrapper) {
          wrappers.set(node.id.name, wrapper);
        }
      }
    },
  });

  walk(ast, {
    leave(node) {
      if (
        node.type !== "CallExpression"
        || node.callee.type !== "Identifier"
        || !wrappers.has(node.callee.name)
        || node.arguments.length !== 1
        || !isStringLiteral(node.arguments[0])
      ) {
        return;
      }

      const wrapper = wrappers.get(node.callee.name);
      const input = node.arguments[0].value;
      if (wrapper === "identity") {
        this.replace(literal(input));
      } else if (wrapper === "atob") {
        const decoded = decodeBase64(input);
        if (decoded !== null) {
          this.replace(literal(decoded));
        }
      } else if (wrapper === "decodeURIComponent") {
        try {
          this.replace(literal(decodeURIComponent(input)));
        } catch (_err) {
          // Keep malformed URI literals unchanged.
        }
      }
    },
  });
}

function describeWrapper(params, body) {
  if (params.length !== 1 || params[0].type !== "Identifier") {
    return null;
  }

  let expression = body;
  if (body.type === "BlockStatement") {
    if (body.body.length !== 1 || body.body[0].type !== "ReturnStatement" || !body.body[0].argument) {
      return null;
    }
    expression = body.body[0].argument;
  }

  if (expression.type === "Identifier" && expression.name === params[0].name) {
    return "identity";
  }
  if (
    expression.type === "CallExpression"
    && expression.callee.type === "Identifier"
    && (expression.callee.name === "atob" || expression.callee.name === "decodeURIComponent")
    && expression.arguments.length === 1
    && expression.arguments[0].type === "Identifier"
    && expression.arguments[0].name === params[0].name
  ) {
    return expression.callee.name;
  }
  return null;
}

function cleanupStaticDeadCode(ast) {
  walk(ast, {
    leave(node) {
      if (node.type === "IfStatement" && isBooleanLiteral(node.test)) {
        if (node.test.value) {
          this.replace(node.consequent);
        } else if (node.alternate) {
          this.replace(node.alternate);
        } else {
          this.replace({ type: "EmptyStatement" });
        }
        return;
      }
      if (node.type === "ConditionalExpression" && isBooleanLiteral(node.test)) {
        this.replace(node.test.value ? node.consequent : node.alternate);
      }
    },
  });
}

function isIdentifierName(value) {
  return /^[A-Za-z_$][\w$]*$/.test(value);
}

function isStringLiteral(node) {
  return node && node.type === "Literal" && typeof node.value === "string";
}

function isIntegerLiteral(node) {
  return node && node.type === "Literal" && Number.isInteger(node.value) && node.value >= 0;
}

function isBooleanLiteral(node) {
  return node && node.type === "Literal" && typeof node.value === "boolean";
}

function literal(value) {
  return {
    type: "Literal",
    value,
    raw: JSON.stringify(value),
  };
}

function identifier(name) {
  return {
    type: "Identifier",
    name,
  };
}

function ensureTrailingNewline(value) {
  return value.endsWith("\n") ? value : value + "\n";
}
