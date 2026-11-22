// Adds "English / 简体中文" and "API" links to the menu bar. Both books have the same file tree,
// so the other language's page is the same path under ../<lang>/. Works under any base path
// (`/akio/` on GitHub Pages, `/` when served locally). Kept identical in book/en and book/zh-CN.
(function () {
  var langs = [
    ["en", "English"],
    ["zh-CN", "简体中文"],
  ];
  var here = document.documentElement.lang;
  // mdBook defines `path_to_root` ("" or "../" ...) on every page; 404.html also sets <base>.
  var root = new URL(typeof path_to_root === "string" ? path_to_root : "", document.baseURI);
  var site = new URL("../", root);
  var href = location.href;
  var inBook = href.indexOf(root.href) === 0;
  var rel = inBook ? href.slice(root.href.length) : "";

  // The site-wide 404 page is the English one; send Chinese paths to the Chinese 404 page.
  if (!inBook && here === "en" && location.pathname.indexOf("/zh-CN/") >= 0) {
    location.replace(new URL("zh-CN/404.html", site).href);
    return;
  }

  var bar = document.querySelector(".right-buttons");
  if (!bar) return;
  var box = document.createElement("span");
  box.className = "akio-lang-switch";
  box.style.cssText = "margin: 0 0.5em; font-size: 0.9em; white-space: nowrap;";
  langs.forEach(function (l, i) {
    if (i > 0) box.appendChild(document.createTextNode(" | "));
    if (l[0] === here) {
      var b = document.createElement("b");
      b.textContent = l[1];
      box.appendChild(b);
    } else {
      var a = document.createElement("a");
      a.href = new URL(l[0] + "/" + rel, site).href;
      a.hreflang = l[0];
      a.lang = l[0];
      a.textContent = l[1];
      box.appendChild(a);
    }
  });
  box.appendChild(document.createTextNode(" | "));
  var api = document.createElement("a");
  api.href = new URL("api/akio/index.html", site).href;
  api.textContent = "API";
  api.title = here === "zh-CN" ? "API 文档 (rustdoc)" : "API documentation (rustdoc)";
  box.appendChild(api);
  bar.insertBefore(box, bar.firstChild);
})();
