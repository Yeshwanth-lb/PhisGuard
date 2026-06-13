"""Redis-backed async cache for Layer 1 OSINT results."""
import json
import hashlib
import structlog
from typing import Optional

logger = structlog.get_logger()

try:
    import redis.asyncio as aioredis
    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False


class L1Cache:
    """Async Redis cache wrapper. TTL defaults to 1 hour."""

    def __init__(self, redis_url: str = "redis://localhost:6379", ttl: int = 3600):
        self._url = redis_url
        self._ttl = ttl
        self._client = None

    async def connect(self) -> None:
        if _REDIS_AVAILABLE:
            self._client = aioredis.from_url(self._url, decode_responses=True)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    def _make_key(self, source: str, ioc: str) -> str:
        h = hashlib.md5(ioc.encode()).hexdigest()
        return f"pg:l1:{source}:{h}"

    async def get(self, source: str, ioc: str) -> Optional[dict]:
        if not self._client:
            return None
        try:
            raw = await self._client.get(self._make_key(source, ioc))
            if raw:
                logger.debug("l1_cache_hit", source=source)
                return json.loads(raw)
        except Exception as exc:
            logger.warning("l1_cache_get_err", error=str(exc))
        return None

    async def set(self, source: str, ioc: str, data: dict) -> None:
        if not self._client:
            return
        try:
            await self._client.setex(
                self._make_key(source, ioc),
                self._ttl,
                json.dumps(data),
            )
        except Exception as exc:
            logger.warning("l1_cache_set_err", error=str(exc))
