"""
Various parsers for network scanning tool output formts.
"""

all = [ 'reports', 'mbsa', 'nessus', 'nipper', 'nmap', 'script' ]

class ReportParserError(Exception):
    def __str__(self):
        return str(self.args[0])

