"""mitmproxy entry point: Burp-style site map and repeater pages.

    mitmproxy -s burpmap.py

mitmproxy puts this file's directory on sys.path while it loads the script, so
the `burpmap` package next to it imports cleanly. All imports must happen at
module level - the path entry is removed again once loading finishes.
"""

from burpmap.addon import BurpMap

addons = [BurpMap()]
