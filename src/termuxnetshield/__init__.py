"""
TermuxNetShield v2.1 - Pi-hole Edition
Sistema de bloqueio de anúncios e proteção DNS para Termux
"""

__version__ = "2.1.0"
__author__ = "TermuxNetShield Team"
__license__ = "MIT"

from .dns.server import DNSServer
from .web.dashboard import WebDashboard
from .blocklist.manager import BlocklistManager
from .analyzer.stats import StatsAnalyzer

__all__ = [
    'DNSServer',
    'WebDashboard', 
    'BlocklistManager',
    'StatsAnalyzer',
    '__version__'
]
