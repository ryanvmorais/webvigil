"""
Web API: a FastAPI wrapper around the scan engine, with SQLite persistence.

Only available with the ``web`` extra (``pip install "webvigil[web]"``). This
package may import the engine and the reporters; the engine imports nothing from
here — the boundary is enforced by import-linter.
"""
