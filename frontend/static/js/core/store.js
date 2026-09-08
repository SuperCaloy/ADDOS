// Centralized frontend reactive state store with publish-subscribe notification channels.
// Decouples shared state management across telemetry cards, charts, theme toggles, and expert view.

(function () {
  // Reactive property dictionary and topic subscriber registry.
  const _state = {
    ifThreshold: 0,
    chartRange: 'Live',
    theme: localStorage.getItem('adddos-theme') || 'dark',
    expertActive: localStorage.getItem('addos-expert') === '1',
  };

  const _subscribers = new Map();

  // Binds an observer callback to a designated state key, returning an unsubscribe cleanup closure.
  // Allows modular UI controllers to react to state changes without direct cross-module coupling.
  function subscribe(key, callback) {
    if (!_subscribers.has(key)) _subscribers.set(key, new Set());
    _subscribers.get(key).add(callback);
    return () => _subscribers.get(key).delete(callback);
  }

  // Dispatches updated property values to all callbacks registered for that key.
  // Safeguards the notification loop by catching and logging individual subscriber errors.
  function _notify(key, value) {
    if (_subscribers.has(key)) {
      _subscribers.get(key).forEach(cb => {
        try { cb(value); } catch (e) { console.error('Store subscriber error:', e); }
      });
    }
  }

  // Public accessors and mutators synchronizing state values, storage persistence, and subscriber updates.
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

