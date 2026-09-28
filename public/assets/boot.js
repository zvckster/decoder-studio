// Applies the saved theme and display size before the first paint (no flash).
(function () {
  try {
    var t = localStorage.getItem('wds.theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) {}
  try {
    var s = JSON.parse(localStorage.getItem('wds.settings') || '{}');
    if (s.uiScale) document.documentElement.style.setProperty('--ui-scale', s.uiScale);
  } catch (e) {}
})();
