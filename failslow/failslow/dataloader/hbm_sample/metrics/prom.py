from prometheus_client.values import MutexValue
from prometheus_client.samples import Sample
from prometheus_client import Gauge
from typing import Iterable, Callable


class TimestampedMutexValue(MutexValue):
    def set(self, value, timestamp=None):
        with self._lock:
            self._value = value
            self._timestamp = timestamp
    
    def get(self):
        with self._lock:
            return self._value, self._timestamp
    
class TimestampedGauge(Gauge):
    def _metric_init(self) -> None:
        self._value = TimestampedMutexValue(
            self._type, self._name, self._name, self._labelnames, self._labelvalues,
            self._documentation, multiprocess_mode=self._multiprocess_mode
        )
    
    def set(self, value, timestamp=None):
        if timestamp is None:
            timestamp = time.time()
        self._value.set(float(value), timestamp)
    
    def _child_samples(self) -> Iterable[Sample]:
        v, t = self._value.get()
        return (Sample('', {}, v, t, None),)
