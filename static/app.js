// Phones: start the project-page sections closed so the user picks what to open.
// Desktop (and forced Desktop view) keeps everything open. Without this script all stays open.
(function () {
  if (!window.matchMedia || !window.matchMedia("(max-width: 959px)").matches) return;
  var hash = decodeURIComponent(location.hash.slice(1));
  var target = hash ? document.getElementById(hash) : null;
  var all = document.querySelectorAll("details.msec, details.sub");
  for (var i = 0; i < all.length; i++) {
    var d = all[i];
    if (d.hasAttribute("data-keep-open")) continue;
    if (target && d.classList.contains("msec") && target.contains(d)) continue; // section we jumped to
    d.open = false;
  }
  if (target) { target.scrollIntoView(); }
})();
