/* store.js: Centralized frontend state store
 * Encapsulates cross-module shared state (IF threshold, chart range, theme)
 * with explicit getters, setters, and event notifications. */

(function () {
  const _state = {
    ifThreshold: 0,
    chartRange: 'Live',
    theme: localStorage.getItem('adddos-theme') || 'dark',
    expertActive: localStorage.getItem('addos-expert') === '1',
  };

  const _subscribers = new Map();

  function subscribe(key, callback) {
    if (!_subscribers.has(key)) _subscribers.set(key, new Set());
    _subscribers.get(key).add(callback);
    return () => _subscribers.get(key).delete(callback);
  }

  function _notify(key, value) {
    if (_subscribers.has(key)) {
      _subscribers.get(key).forEach(cb => {
        try { cb(value); } catch (e) { console.error('Store subscriber error:', e); }
      });
    }
  }

  const Store = {
    getIfThreshold: () => _state.ifThreshold,
    setIfThreshold: (val) => {
      _state.ifThreshold = val;
      window.ifThr = val;
      _notify('ifThreshold', val);
    },

    getChartRange: () => _state.chartRange,
    setChartRange: (r) => {
      _state.chartRange = r;
      _notify('chartRange', r);
    },

    getTheme: () => _state.theme,
    setTheme: (light) => {
      const mode = light ? 'light' : 'dark';
      _state.theme = mode;
      localStorage.setItem('adddos-theme', mode);
      _notify('theme', light);
    },

    isExpertActive: () => _state.expertActive,
    setExpertActive: (active) => {
      _state.expertActive = !!active;
      localStorage.setItem('addos-expert', active ? '1' : '0');
      _notify('expertActive', _state.expertActive);
    },

    subscribe,
  };

  window.Store = Store;
})();
