"""Vercel entry point for the OmniJarvis light worker.

Vercel's Python runtime serves files under api/ as serverless
functions. This file re-exports the FastAPI app from main.py (project
root = render/worker, on sys.path for api functions). All routes
(/health, /smoke/pdf, /doc/*, /mem/extract, /browse/run) are served
by the single function; vercel.json rewrites every path here.
"""
from main import app

__all__ = ["app"]
