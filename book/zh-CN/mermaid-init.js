// Renders ```mermaid code blocks as diagrams (the same Markdown renders natively on GitHub).
// Kept identical in book/en and book/zh-CN.
(function () {
  var blocks = document.querySelectorAll("code.language-mermaid");
  if (blocks.length === 0) return;
  var s = document.createElement("script");
  s.src = "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js";
  s.onload = function () {
    var dark = /(coal|navy|ayu)/.test(document.documentElement.className);
    blocks.forEach(function (code) {
      var div = document.createElement("div");
      div.className = "mermaid";
      div.textContent = code.textContent;
      code.parentElement.replaceWith(div);
    });
    window.mermaid.initialize({ startOnLoad: false, theme: dark ? "dark" : "default" });
    window.mermaid.run();
  };
  document.head.appendChild(s);
})();
