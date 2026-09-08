// Unified Server-Sent Events (SSE) EventBus managing the live telemetry stream.
// Maintains a single EventSource connection and dispatches typed payloads to avoid redundant HTTP requests.

(function () {
  // Internal connection handle, reconnection timer, and topic subscriber map.
  let _es = null;
  let _reconnectTimer = null;
  const _listeners = new Map();
  let _status = 'disconnected';

  // Registers an event listener callback for a designated topic channel.
  // Enables modular UI components to observe streaming telemetry independently.
  function on(type, callback) {
    if (!_listeners.has(type)) {
      _listeners.set(type, new Set());
    }
    _listeners.get(type).add(callback);
  }

  // Unregisters an existing event listener callback from a topic channel.
  // Cleans up event bindings when components or visualizers are torn down.
  function off(type, callback) {
    if (_listeners.has(type)) {
      _listeners.get(type).delete(callback);
    }
  }

  // Dispatches an event payload to all callbacks subscribed to the specified topic.
  // Isolates callback execution inside try-catch blocks to prevent broken subscribers from halting the bus.
  function emit(type, data) {
    if (_listeners.has(type)) {
      _listeners.get(type).forEach(cb => {
        try { cb(data); } catch (err) { console.error('EventBus listener error:', err); }
      });
    }
  }

  // Establishes a persistent Server-Sent Events stream to the backend /api/events endpoint.
  // Parses incoming JSON payloads, demultiplexes expert telemetry from audit events, and schedules reconnection on error.
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

  // Closes the active EventSource stream and notifies subscribers of the disconnected state.
  // Halts background network consumption when live streaming is no longer required.
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

