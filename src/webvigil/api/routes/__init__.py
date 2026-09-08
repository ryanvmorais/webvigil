"""
FastAPI routers, one module per resource group.

``meta`` (health / checks / defaults), ``setup`` (first-run), ``auth``
(login / logout / me / password), ``scans`` (CRUD + queue + findings), and
``reports`` (download). Every router is mounted under ``/api``.
"""
