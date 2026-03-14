"""Web server package — FastAPI-based dashboard for ArchGraph."""

from archgraph.server.web import create_app, run_server

__all__ = ["create_app", "run_server"]
