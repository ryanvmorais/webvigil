"""Check plugins.

Each check subclasses ``Check``, declares its metadata, and implements
``async run(ctx) -> list[Finding]``. Checks are registered with the ``@register``
decorator and discovered via entry points.
"""
