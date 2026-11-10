// Phones only: open the tab that holds the section we were sent to (e.g. after saving a key),
// and start the long lists (release history, existing keys…) closed. Desktop shows everything.
(function () {
  if (!window.matchMedia || !window.matchMedia("(max-width: 959px)").matches) return;
  var hash = decodeURIComponent(location.hash.slice(1));
  var target = hash ? document.getElementById(hash) : null;
  if (target) {
    var pane = target.closest(".tabpane");
    if (pane && !pane.classList.contains("active")) {
      var panes = document.querySelectorAll(".tabpane");
      for (var i = 0; i < panes.length; i++) panes[i].classList.toggle("active", panes[i] === pane);
      var tabs = document.querySelectorAll(".tabs a");
      for (var j = 0; j < tabs.length; j++) tabs[j].classList.toggle("on", tabs[j].getAttribute("data-tab") === pane.getAttribute("data-tab"));
    }
  }
  var subs = document.querySelectorAll("details.sub");
  for (var k = 0; k < subs.length; k++) {
    if (!subs[k].hasAttribute("data-keep-open")) subs[k].open = false;
  }
  if (target) target.scrollIntoView();
})();
