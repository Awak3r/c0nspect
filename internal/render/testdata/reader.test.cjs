"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const katex = require("../static/katex.min.js");
const reader = fs.readFileSync(path.join(__dirname, "../static/reader.js"), "utf8");

function formula(source, { mode = "inline", tagName = "SPAN", inCode = false } = {}) {
  const attributes = new Map([["data-tex", source], ["data-math", mode]]);
  return {
    tagName,
    childNodes: ["$" + source + "$"],
    getAttribute(name) { return attributes.has(name) ? attributes.get(name) : null; },
    closest(selector) {
      assert.equal(selector, "pre, code");
      return inCode ? {} : null;
    },
    replaceChildren(...children) { this.childNodes = children; },
  };
}

function runReader(elements, render, readyState = "complete") {
  let onReady;
  const document = {
    readyState,
    querySelectorAll(selector) {
      assert.equal(selector, ".math[data-tex][data-math]");
      return elements;
    },
    createElement(tag) {
      assert.equal(tag, "span");
      return { childNodes: [] };
    },
    addEventListener(event, callback, options) {
      assert.equal(event, "DOMContentLoaded");
      assert.equal(options.once, true);
      onReady = callback;
    },
  };
  const window = { katex: render ? { render } : undefined };
  vm.runInNewContext(reader, { window, document }, { timeout: 1000 });
  return { onReady };
}

function optionsFor(source, mode = "inline") {
  let options;
  runReader([formula(source, { mode })], (_source, target, opts) => {
    options = opts;
    target.childNodes = ["rendered"];
  });
  assert.ok(options, "formula did not reach KaTeX");
  return options;
}

test("reader passes exact source and bounded, untrusted options to KaTeX", () => {
  const source = "\\frac{a_b}{c} + \\\\ + <img src=x> & \"quoted\"";
  const elements = [formula(source), formula("x_1", { mode: "block", tagName: "DIV" })];
  const calls = [];
  runReader(elements, (tex, target, options) => {
    calls.push({ tex, options });
    target.childNodes = ["rendered"];
  });
  assert.equal(calls.length, 2);
  assert.equal(calls[0].tex, source);
  assert.equal(calls[0].options.displayMode, false);
  assert.equal(calls[1].options.displayMode, true);
  for (const { options } of calls) {
    assert.equal(options.trust, false);
    assert.equal(options.throwOnError, false);
    assert.equal(options.strict, "error");
    assert.equal(options.maxExpand, 1000);
    assert.equal(options.maxSize, 20);
    assert.equal(options.globalGroup, false);
    assert.equal(options.output, "htmlAndMathml");
    assert.equal(Object.getPrototypeOf(options.macros), null);
  }
  assert.notEqual(calls[0].options.macros, calls[1].options.macros);
  assert.deepEqual(elements[0].childNodes, ["rendered"]);
});

test("reader ignores code, oversized source, and invalid markers", () => {
  const elements = [
    formula("x", { inCode: true }),
    formula("x".repeat(16 * 1024 + 1)),
    formula("x", { mode: "invalid" }),
    formula("x", { tagName: "SCRIPT" }),
    formula(null),
  ];
  runReader(elements, () => assert.fail("invalid formula reached KaTeX"));
  for (const element of elements) assert.equal(element.childNodes.length, 1);
});

test("missing KaTeX and unexpected errors preserve visible source", () => {
  const missing = formula("x_1");
  runReader([missing]);
  assert.deepEqual(missing.childNodes, ["$x_1$"]);
  const broken = formula("x_2");
  runReader([broken], (_source, target) => {
    target.childNodes = ["partially rendered"];
    throw new Error("unexpected rendering error");
  });
  assert.deepEqual(broken.childNodes, ["$x_2$"]);
});

test("reader waits for DOMContentLoaded when not deferred", () => {
  let calls = 0;
  const { onReady } = runReader([formula("x")], (_source, target) => {
    calls++;
    target.childNodes = ["rendered"];
  }, "loading");
  assert.equal(calls, 0);
  onReady();
  assert.equal(calls, 1);
});

test("vendored KaTeX renders inline formulas and multiline matrices", () => {
  assert.equal(katex.version, "0.19.1");
  const inline = "\\frac{a_b}{c^2}";
  const block = "\\begin{pmatrix}\na & b \\\\\nc & d\n\\end{pmatrix}";
  const aligned = "\\begin{aligned}\nx &= 1 \\\\\ny &= 2\n\\end{aligned}";
  for (const [source, mode] of [[inline, "inline"], [block, "block"], [aligned, "block"]]) {
    const output = katex.renderToString(source, optionsFor(source, mode));
    assert.ok(output.includes("katex-mathml"));
    assert.ok(!output.includes("katex-error"), "valid TeX fell back to source");
    if (mode === "block") {
      assert.ok(output.includes("katex-display"));
      assert.ok(output.includes("<mtable"));
    }
  }
});

test("KaTeX trust false blocks TeX links, images, HTML, and filesystem commands", () => {
  const attacks = [
    "\\href{javascript:alert(1)}{click}",
    "\\url{https://evil.test/track}",
    "\\includegraphics{https://evil.test/track}",
    "\\includegraphics{data:image/svg+xml;base64,PHN2Zz4=}",
    "\\htmlClass{math}{x}",
    "\\htmlId{injected}{x}",
    "\\htmlStyle{background-image:url(https://evil.test/track)}{x}",
    "\\htmlData{evil=injected}{x}",
    "\\input{/etc/passwd}",
    "\\write18{arbitrary-command}",
    "\\text{\"</span><img src=x onerror=alert(1)>}",
  ];
  for (const source of attacks) {
    const output = katex.renderToString(source, optionsFor(source));
    assert.doesNotMatch(output, /<(a|img|script|iframe|object|button)\b/i);
    assert.doesNotMatch(output, /<[^>]+\s(href|src|onerror|onload|data-evil)=/i);
    assert.doesNotMatch(output, /<[^>]+id="injected"/i);
  }
});

test("invalid and recursively expanding TeX has a visible bounded fallback", () => {
  for (const source of ["\\frac{", "\\def\\readerLoop{\\readerLoop}\\readerLoop"]) {
    const output = katex.renderToString(source, optionsFor(source));
    assert.ok(output.includes("katex-error"));
    assert.ok(output.includes("title="));
  }
  const rule = "\\rule{10000em}{10000em}";
  const output = katex.renderToString(rule, optionsFor(rule));
  assert.ok(output.includes("border-right-width:20em"));
  assert.doesNotMatch(output, /style="[^"]*10000em/);
});

test("global TeX macro definitions do not cross formula boundaries", () => {
  const first = "\\gdef\\readerScoped{X}\\readerScoped";
  const second = "\\readerScoped";
  const firstOptions = optionsFor(first);
  const secondOptions = optionsFor(second);
  katex.renderToString(first, firstOptions);
  assert.ok(Object.hasOwn(firstOptions.macros, "\\readerScoped"));
  assert.ok(!Object.hasOwn(secondOptions.macros, "\\readerScoped"));
  const output = katex.renderToString(second, secondOptions);
  assert.ok(output.includes("\\readerScoped"));
});
