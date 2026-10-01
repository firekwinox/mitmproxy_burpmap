"""Burp-style site map and repeater pages for mitmproxy's console UI.

The entry point for ``mitmproxy -s`` is ``burpmap.py`` one directory up; it
imports :class:`burpmap.addon.BurpMap`. Nothing is imported here so that the
pure-Python parts (``model``, ``discovery``) stay importable without urwid.
"""
