/**
 * totp.js — TOTP setup page helpers
 *
 * Click the secret-key element to copy it to the clipboard.
 */

(function () {
  'use strict';

  var secretEl = document.getElementById('totp-secret');
  if (!secretEl) return;

  secretEl.title = 'Click to copy';

  secretEl.addEventListener('click', function () {
    var text = secretEl.dataset.secret || secretEl.textContent.trim();

    if (!navigator.clipboard) {
      /* Fallback: select the text so the user can Ctrl+C */
      var range = document.createRange();
      range.selectNodeContents(secretEl);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      return;
    }

    navigator.clipboard.writeText(text).then(function () {
      var orig = secretEl.textContent;
      secretEl.textContent = '✓ Copied!';
      setTimeout(function () {
        secretEl.textContent = orig;
      }, 1800);
    });
  });

})();
