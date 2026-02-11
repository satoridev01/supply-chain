"""
Supply-Chain Scanner Test Project
=================================
⚠️  DO NOT EXECUTE THIS FILE — it is for static analysis / scanner testing only.

This file simulates a Python project that imports both legitimate and
typosquatted (malicious) packages. A good supply-chain scanner should
flag the malicious imports and/or the corresponding entries in requirements.txt.
"""

# --- Legitimate imports (should NOT be flagged) ---
import requests
import colorama
from dateutil import parser as dateutil_parser
import jellyfish
from bs4 import BeautifulSoup
import urllib3
from flask import Flask
import numpy as np
import setuptools

# --- Typosquat / malicious imports (SHOULD be flagged) ---
import python3_dateutil        # typosquat of python-dateutil
import jeIlyfish               # uppercase I instead of lowercase L
import colourama               # typosquat of colorama
import requesocks              # typosquat of requests
import beautifulsup            # typosquat of beautifulsoup4
import urlib3                  # typosquat of urllib3
import flaask                  # typosquat of flask
import setuptool               # typosquat of setuptools
import numppy                  # typosquat of numpy


def main():
    """Simulated application entry point."""
    print("If your scanner didn't flag anything, it needs work.")


if __name__ == "__main__":
    main()
