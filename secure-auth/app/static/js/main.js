/**
 * main.js — UI enhancements for CampusConnect
 *
 * 1. Password strength meter on the registration form
 * 2. Auto-dismiss flash messages after a few seconds
 */

(function () {
  'use strict';

  /* ── 1. Password strength meter ────────────────────────────────────────── */

  var pwInput = document.getElementById('password');
  var fillEl  = document.getElementById('strength-fill');
  var textEl  = document.getElementById('strength-text');

  if (pwInput && fillEl) {
    pwInput.addEventListener('input', function () {
      var score = measureStrength(this.value);
      var levels = [
        { pct: '0%',    color: 'transparent',  label: '' },
        { pct: '25%',   color: '#f87171',       label: 'Weak' },
        { pct: '50%',   color: '#fb923c',       label: 'Fair' },
        { pct: '75%',   color: '#facc15',       label: 'Good' },
        { pct: '100%',  color: '#64ffda',       label: 'Strong' }
      ];
      var lvl = levels[score];
      fillEl.style.width      = lvl.pct;
      fillEl.style.background = lvl.color;
      if (textEl) {
        textEl.textContent = this.value.length > 0 ? lvl.label : '';
        textEl.style.color = lvl.color;
      }
    });
  }

  /** Score 0–4 based on complexity rules. */
  function measureStrength(pw) {
    if (!pw) return 0;
    var score = 0;
    if (pw.length >= 12)                            score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw))      score++;
    if (/\d/.test(pw))                              score++;
    if (/[^A-Za-z0-9]/.test(pw))                   score++;
    return score;
  }

  /* ── 2. Auto-dismiss flash messages ────────────────────────────────────── */

  var flashes = document.querySelectorAll('.flash:not(.flash-otp)');
  flashes.forEach(function (el) {
    setTimeout(function () {
      el.style.transition = 'opacity 0.4s ease';
      el.style.opacity    = '0';
      setTimeout(function () {
        if (el.parentNode) el.parentNode.removeChild(el);
      }, 400);
    }, 5500);
  });

})();
