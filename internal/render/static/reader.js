(() => {
  "use strict";

  // The Go renderer also limits each formula to 16 KiB before adding data-tex.
  const maxSourceLength = 16 * 1024;

  function renderMath() {
    if (!window.katex || typeof window.katex.render !== "function") return;

    for (const element of document.querySelectorAll(".math[data-tex][data-math]")) {
      if (!['SPAN', 'DIV'].includes(element.tagName) || element.closest("pre, code")) continue;
      const mode = element.getAttribute("data-math");
      const source = element.getAttribute("data-tex");
      if ((mode !== "inline" && mode !== "block") || source === null || source.length > maxSourceLength) continue;

      try {
        // Render off-DOM so an unexpected error cannot destroy the source fallback.
        const target = document.createElement("span");
        window.katex.render(source, target, {
          displayMode: mode === "block",
          output: "htmlAndMathml",
          trust: false,
          throwOnError: false,
          strict: "error",
          maxExpand: 1000,
          maxSize: 20,
          macros: Object.create(null),
          globalGroup: false,
        });
        element.replaceChildren(...target.childNodes);
      } catch (_) {
        // Keep the original, escaped source visible. Do not log note contents.
      }
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", renderMath, { once: true });
  } else {
    renderMath();
  }
})();
