import time
from threading import Lock

class TTLCache:
    def __init__(self, max_items=1000, ttl_seconds=3600):
        self.store = {}
        self.ttl = ttl_seconds
        self.max_items = max_items
        self.lock = Lock()

    def get(self, key):
        with self.lock:
            v = self.store.get(key)
            if not v:
                return None
            expiry, val = v
            if time.time() > expiry:
                del self.store[key]
                return None
            return val

    def set(self, key, value):
        with self.lock:
            if len(self.store) > self.max_items:
                try:
                    self.store.pop(next(iter(self.store)))
                except StopIteration:
                    pass
            self.store[key] = (time.time() + self.ttl, value)

    def clear(self):
        with self.lock:
            self.store.clear()
