/* events.js: Unified Server-Sent Events (SSE) EventBus
 * Maintains a single EventSource connection to /api/events and dispatches
 * typed payloads to subscribed listeners, eliminating duplicate network streams. */

(function () {
  let _es = null;
  let _reconnectTimer = null;
  const _listeners = new Map();
  let _status = 'disconnected';

  function on(type, callback) {
    if (!_listeners.has(type)) {
      _listeners.set(type, new Set());
    }
    _listeners.get(type).add(callback);
  }

  function off(type, callback) {
    if (_listeners.has(type)) {
      _listeners.get(type).delete(callback);
    }
  }

  function emit(type, data) {
    if (_listeners.has(type)) {
      _listeners.get(type).forEach(cb => {
        try { cb(data); } catch (err) { console.error('EventBus listener error:', err); }
      });
    }
  }

  function connect() {
    if (_es) return;
    const apiUrl = window.API_URL || (typeof API !== 'undefined' ? API : '');
    if (!apiUrl) return;

    if (_reconnectTimer) {
      clearTimeout(_reconnectTimer);
      _reconnectTimer = null;
    }

    _es = new EventSource(`${apiUrl}/api/events`);
    _status = 'connecting';
    emit('statuschange', _status);

    _es.onopen = () => {
      _status = 'connected';
      emit('statuschange', _status);
    };

    _es.onmessage = e => {
      try {
        const parsed = JSON.parse(e.data);
        emit('raw', parsed);

        if (parsed.type === 'expert' && parsed.payload) {
          emit('expert', parsed.payload);
        } else {
          const ev = parsed.payload || parsed;
          emit('event', ev);
        }
      } catch (_) {}
    };

    _es.onerror = () => {
      disconnect();
      _status = 'error';
      emit('statuschange', _status);
      _reconnectTimer = setTimeout(connect, 3000);
    };
  }

  function disconnect() {
    if (_es) {
      _es.close();
      _es = null;
    }
    _status = 'disconnected';
    emit('statuschange', _status);
  }

  window.EventBus = {
    on,
    off,
    emit,
    connect,
    disconnect,
    getStatus: () => _status,
  };
})();
