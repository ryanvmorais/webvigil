"""
Vendored Public Suffix List (see PROVENANCE.json).

Holds ``public_suffix_list.dat`` (the list as publicsuffix.org serves it, MPL-2.0 header
included) and ``PROVENANCE.json`` (where it came from and when). Loaded through
:mod:`importlib.resources`, never a path relative to the source tree; refreshed by
``scripts/update-public-suffix-list.py``.
"""
