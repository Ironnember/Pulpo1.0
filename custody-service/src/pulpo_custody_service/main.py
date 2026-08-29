"""Uvicorn entrypoint for Hostile Worker V0 sandbox custody service."""

from .runtime import create_runtime_app

app = create_runtime_app()
