"""
Rate limiting middleware
"""
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import time
from collections import defaultdict, deque
from typing import Dict, Deque

from api.core.config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware"""

    def __init__(self, app, calls: int = None, period: int = 60):
        super().__init__(app)
        self.calls = calls or settings.rate_limit_per_minute
        self.period = period
        self.clients: Dict[str, Deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        # Get client IP
        client_ip = request.client.host

        # Skip rate limiting for health checks
        if request.url.path == "/health":
            return await call_next(request)

        # Current time
        now = time.time()

        # Clean old requests
        client_requests = self.clients[client_ip]
        while client_requests and client_requests[0] <= now - self.period:
            client_requests.popleft()

        # Check rate limit
        if len(client_requests) >= self.calls:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )

        # Add current request
        client_requests.append(now)

        # Process request
        response = await call_next(request)
        return response
