/**
 * Shared right-side panel shell for docked panels (IP Threat Analysis, Expert algorithm details).
 * Owns open/close, drag resize, width persistence, and single-panel arbitration.
 * Content rendering and data polling stay in the caller modules.
 */

var SidePanel = (function() {
  var DEFAULT_W = 480;
  var MIN_W = 360;
  var _returnFocus = null;

  function _panel(id) { return document.getElementById(id); }

  function _app() { return document.getElementById('app'); }

  function _clamp(w) {
    var max = Math.floor(window.innerWidth * 0.6);
    if (w < MIN_W) return MIN_W;
    if (w > max) return max;
    return Math.round(w);
  }

  function _savedWidth(storageKey) {
    try {
      var v = parseInt(localStorage.getItem(storageKey), 10);
      if (!isNaN(v)) return _clamp(v);
    } catch (_) {}
    return _clamp(DEFAULT_W);
  }

  function _applyWidth(panel, w) {
    panel.style.width = w + 'px';
    var app = _app();
    if (app) {
      app.style.marginRight = w + 'px';
      app.classList.add('drawer-open');
    }
  }

  // Focus without scrolling the page. A plain focus() scrolls the dashboard
  // to the focused element, which yanks the user's scroll position on open/close.
  function _focusNoScroll(el) {
    if (!el || typeof el.focus !== 'function') return;
    try { el.focus({ preventScroll: true }); } catch (_) { el.focus(); }
  }

  // Closes every open side panel except the given id. Keeps panels from stacking.
  function closeAll(exceptId) {
    var open = document.querySelectorAll('.side-panel.open');
    for (var i = 0; i < open.length; i++) {
      if (open[i].id !== exceptId) close(open[i].id);
    }
  }

  function open(id, opts) {
    opts = opts || {};
    var panel = _panel(id);
    if (!panel) return;
    closeAll(id);
    _returnFocus = document.activeElement;
    var w = _savedWidth(opts.storageKey || ('side-panel-' + id));
    _applyWidth(panel, w);
    panel.classList.add('open');
    panel.setAttribute('aria-hidden', 'false');
    if (opts.focusSel) {
      requestAnimationFrame(function() {
        _focusNoScroll(panel.querySelector(opts.focusSel));
      });
    }
  }

  function close(id) {
    var panel = _panel(id);
    if (!panel) return;
    panel.classList.remove('open');
    panel.setAttribute('aria-hidden', 'true');
    var app = _app();
    if (app) { app.style.marginRight = ''; app.classList.remove('drawer-open'); }
    _focusNoScroll(_returnFocus);
    _returnFocus = null;
  }

  function isOpen(id) {
    var panel = _panel(id);
    return !!(panel && panel.classList.contains('open'));
  }

  // Binds a left-edge drag handle that resizes the panel and persists the width.
  function initResize(panelId, handleId, storageKey) {
    var panel = _panel(panelId);
    var handle = document.getElementById(handleId);
    if (!panel || !handle) return;
    var dragging = false, startX = 0, startW = 0;

    handle.addEventListener('mousedown', function(e) {
      dragging = true;
      startX = e.clientX;
      startW = panel.offsetWidth;
      panel.classList.add('resizing');
      var app = _app();
      if (app) app.classList.add('resizing-margin');
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
      e.preventDefault();
    });

    document.addEventListener('mousemove', function(e) {
      if (!dragging) return;
      _applyWidth(panel, _clamp(startW + (startX - e.clientX)));
    });

    document.addEventListener('mouseup', function() {
      if (!dragging) return;
      dragging = false;
      panel.classList.remove('resizing');
      var app = _app();
      if (app) app.classList.remove('resizing-margin');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      try { localStorage.setItem(storageKey, String(panel.offsetWidth)); } catch (_) {}
    });
  }

  return {
    open: open,
    close: close,
    closeAll: closeAll,
    isOpen: isOpen,
    initResize: initResize,
    DEFAULT_W: DEFAULT_W,
    MIN_W: MIN_W
  };
})();

window.SidePanel = SidePanel;
