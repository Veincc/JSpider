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
    enter(node, parent) {
      if (
        node.type === "Literal"
        && typeof node.value === "string"
        && typeof node.raw === "string"
        && (!parent || parent.type !== "ExpressionStatement")
        && /\\(?:x[0-9a-fA-F]{2}|u(?:[0-9a-fA-F]{4}|\{[0-9a-fA-F]+\}))/.test(node.raw)
      ) {
        node.raw = JSON.stringify(node.value);
      }
    },
  });
}

function foldStringConcatenations(ast) {
  let changed = true;
  while (changed) {
    changed = false;
    walk(ast, {
      leave(node, parent) {
        if (
          node.type === "BinaryExpression"
          && node.operator === "+"
          && isStringLiteral(node.left)
          && isStringLiteral(node.right)
          && (!parent || parent.type !== "ExpressionStatement")
        ) {
          this.replace(literal(node.left.value + node.right.value));
          changed = true;
        }
      },
    });
  }
}

function cleanupStaticDeadCode(ast) {
  walk(ast, {
    leave(node, parent) {
      if (node.type === "IfStatement" && isBooleanLiteral(node.test)) {
        if (!isScopeSafeBranch(node.consequent) || !isScopeSafeBranch(node.alternate)) {
          return;
        }
        const selected = node.test.value ? node.consequent : node.alternate;
        if (isStringExpressionStatement(selected)) {
          return;
        }
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
        const selected = node.test.value ? node.consequent : node.alternate;
        if (parent && parent.type === "ExpressionStatement" && isStringLiteral(selected)) {
          return;
        }
        this.replace(selected);
      }
    },
  });
}

function isScopeSafeBranch(branch) {
  if (!branch) {
    return true;
  }
  let safe = true;
  walk(branch, {
    enter(node) {
      if (
        node.type === "FunctionExpression"
        || node.type === "ArrowFunctionExpression"
        || node.type === "ClassExpression"
      ) {
        this.skip();
        return;
      }
      if (
        node.type === "VariableDeclaration"
        || node.type === "FunctionDeclaration"
        || node.type === "ClassDeclaration"
      ) {
        safe = false;
        this.skip();
      }
    },
  });
  return safe;
}

function isStringLiteral(node) {
  return node && node.type === "Literal" && typeof node.value === "string";
}

function isBooleanLiteral(node) {
  return node && node.type === "Literal" && typeof node.value === "boolean";
}

function isStringExpressionStatement(node) {
  return node && node.type === "ExpressionStatement" && isStringLiteral(node.expression);
}

function literal(value) {
  return {
    type: "Literal",
    value,
    raw: JSON.stringify(value),
  };
}

function ensureTrailingNewline(value) {
  return value.endsWith("\n") ? value : value + "\n";
}
