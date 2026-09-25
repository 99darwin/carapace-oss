"""In-process rate limiting (no Redis).

Limits are per client IP. Behind a proxy, run uvicorn with
``--proxy-headers --forwarded-allow-ips=<proxy>`` so ``request.client`` is
the real caller; client-supplied X-Forwarded-For is never trusted here.
With several server replicas each keeps its own counters.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
