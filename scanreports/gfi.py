#!/usr/bin/env python
"""
Parser for GFI Languard XML reports
"""

import os,logging,sys,time,re,decimal
from lxml import etree

from scanreports import ReportParserError
from seine.address import IPv4Address,IPv6Address

SEVERITY_NAMES = ['Info','Low','Medium','High']

class GFILanguardReport(list):
    def __init__(self,path):
        if not os.path.isfile(path):
            raise ReportParserError('No such file: %s' % path)

        self.path = path
        try:
            self.tree = etree.parse(self.path)
        except etree.XMLSyntaxError,e:
            raise ReportParserError('Error parsing %s: %s' % (self.path,e))
        
        self.scandetails = GFIScanAttributes(self,self.tree.getroot())
        for node in self.tree.find('hosts').findall('host'):
            self.append(GFIScannedHost(self,node))

class GFIScanAttributes(dict):
    def __init__(self,report,node):
        self.report = report
        self.update(node.items())

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            pass
 
class GFIScannedHost(dict):
    def __init__(self,report,node):
        self.report = report
        self.node = node
        self.update([(c.tag,c.text) for c in  filter(lambda c: 
            c.tag not in ['names','apps_installed'],
            self.node.getchildren()
        )])

        try:
            self.address = IPv4Address(self['ip'])
        except ValueError:
            raise ReportParserError('Could not parse %s' % self['ip'])
            

        try:
            self['names'] = [ (n.get('type'),n.get('serv')) \
                for n in self.node.find('names').findall('name')
            ]
        except AttributeError,e:
            self['names'] = []
        try:
            self['apps'] = map(lambda n: 
                GFIInstalledApp(self,n),
                self.node.find('apps_installed').findall('app')
            )
        except AttributeError,e:
            self['apps'] = []

    def __len__(self):
        return len(self['apps'])

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            pass
        raise AttributeError()

class GFIInstalledApp(dict):
    def __init__(self,host,node):
        self.host = host
        self.node = node
        self.update(node.items())

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            pass
 
class GFILanguardSummary(dict):
    def __init__(self):
        self.reports = []
        self.noapps = []
        self.log = logging.getLogger('modules')

    def __getattr__(self,attr):
        if attr == 'hosts':
            return [host.address for report in self.reports for host in report]
        raise AttributeError('No such GFILanguardSummary attribute: %s' % attr)

    def add(self,path):
        report = GFILanguardReport(path)
        for host in report:
            if host.address in self.hosts:
                self.log.debug('Duplicate report for IP %s' % host.address)
                continue
            if len(host) == 0:
                self.noapps.append(host)
                continue
            for app in host.apps:
                if not self.has_key(app.name):
                    self[app.name] = [] 
                self[app.name].append(host)
        self.reports.append(report)

if __name__ == '__main__':
    gfi = GFILanguardSummary()
    for r in sys.argv[1:]:
        gfi.add(r)

    withapps = sorted(list(set(
        [host.address for swhosts in gfi.values() for host in swhosts]
    )))
    for app in sorted(gfi.keys()):
        print app.encode('utf-8')
        hosts = gfi[app]
        for host in sorted(hosts,lambda x,y: cmp(x.address,y.address)):
            print host.address.ipaddress
        print

    print '### Hosts with apps reported (%d total)' % len(withapps)
    for address in withapps:
        print address.ipaddress

    noapps = sorted(gfi.noapps,lambda x,y: cmp(x.address,y.address))
    print '### Hosts with no apps reported (%d total)' % len(noapps)
    for host in noapps:
        print host.address.ipaddress



