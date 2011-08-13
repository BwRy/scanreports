"""
Various parsers for network scanning tool output formts.
"""

all = [ 'mbsa', 'nessus', 'nmap', 'script' ]

class ReportParserError(Exception):
    def __str__(self):
        return str(self.args[0])

