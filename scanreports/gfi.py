#!/usr/bin/env python
# coding=utf-8
"""
Parser for GFI Languard XML reports
"""

import os,logging,sys,time,re,decimal
from lxml import etree

from scanreports import ReportParserError
from seine.address import IPv4Address,IPv6Address

SEVERITY_NAMES = ['Info','Low','Medium','High']

APP_VENDOR_MAP = {
    'Adobe Systems': [
        'Adobe Systems', 'Adobe Systems Incorporated', 'Adobe Systems, Inc.',
    ],
    'Card Tech Services': [ 'CTL', 'Card Tech Services Limited', ],
    'EMC': ['EMC','EMC Corporation'],
    'Fujitsu': ['Fujitsu','FUJITSU'],
    'Huawei': ['Huawei','Huawei technologies'],
    'Intel Corporation': [ 'Intel', 'Intel Corporation', ],
    'Juniper Networks': [ 'Juniper Networks', 'Juniper Networks, Inc.', ],
    'IBM': ['IBM', 'Cognos ULC'],
    'IntraLinks': ['IntraLinks', 'IntraLinks Inc.',],
    'Kofax': ['Kofax','Kofax Image Products',],
    'Lenovo': [ 'Lenovo', 'Lenovo Group Limited.', ],
    'McAfee': [ 'McAfee, Inc.', ],
    'Microsoft': ['Microsoft', 'Microsoft Corporation', ],
    'Oracle': ['Oracle', 'Oracle Corporation'],
    'PFU': ['PFU','PFU LIMITED'],
    'Progress Soft': [
        'Progressoft', 'Progress Soft Corporation ®', 'Progress Soft Corporation', 
    ],
    'Reuters': [
        'Reuters','Reuters America Inc.','Reuters Ltd.',
        'Reuters Messaging Development', 'http://www.reuters.com',
    ],
    'SafeNet': ['SafeNet','SafeNet, Inc.'],
    'Sun Microsystems': [ 'Sun Microsystems', 'Sun Microsystems, Inc.' ],
    'Thomson Reuters': [
        'Thomson Reuters', 'Thomson Reuters America Inc.',
        'Thomson Reuters Limited', 'Thomson Reuters Messaging Development',
    ],
    'UPEK': ['UPEK','UPEK Inc.'],
    'Webex Communications': [
        'Webex Communications','WebEx Communications Inc.',
    ],
    'WinZip Computing': ['Winzip','WinZip Computing, Inc.',],
    'Winbond': ['Winbond Electronics Corporation',],
}

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
        if self['publisher'] != '':
            for name,values in APP_VENDOR_MAP.items():
                if self['publisher'].encode('utf-8') in values:
                    self['publisher'] = name
                    break

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

    def read(self,path):
        report = GFILanguardReport(path)
        for host in report:
            if host.address in self.hosts:
                self.log.debug('Duplicate report for IP %s' % host.address)
                continue
            if len(host) == 0:
                self.noapps.append(host)
                continue
            for app in host.apps:
                name = ' '.join([app.publisher,app.name]).lstrip()
                if not self.has_key(name):
                    self[name] = {
                        'app': app,
                        'hosts': []
                    }
                self[name]['hosts'].append(host)
        self.reports.append(report)

