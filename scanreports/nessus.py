#!/usr/bin/env python
"""
Parser for nessus XML report files
"""

import os,sys,time,re,decimal
from lxml import etree

from scanreports import ReportParserError
from seine.address import IPv4Address,IPv6Address

NESSUS_REPORT_FORMATS = [
    'NessusClientData_v2'
]
NESSUS_PLUGIN_REVISION_MATCHES = [
    re.compile('^\$Revision:\s+(.*)\s+\$$'),
    re.compile('^([0-9.]+)$'),
]

NESSUS_PLUGIN_TYPES = ['combined','local','summary','remote']

XREF_URL_TEMPLATES = {
    'CWE':      'http://cwe.mitre.org/data/definitions/%(id)s.html',
    'OSVDB':    'http://osvdb.org/show/osvdb/%(id)s',
}

class NessusXMLReport(object):
    def __init__(self,path):
        if not os.path.isfile(path):
            raise ReportParserError('No such file: %s' % path)

        self.path = path
        try:
            self.tree = etree.parse(path)
        except etree.XMLSyntaxError,e:
            raise ReportParserError('Error parsing %s: %s' % (self.path,e))

        root = self.tree.getroot()
        if root.tag not in NESSUS_REPORT_FORMATS:
            raise ReportParserError('Unsupported nessus report format: %s' % root.tag) 

        self.preferences = NessusReportPreferences(self.tree.find('Preferences'))
        self.target_families = NessusTargetFamilies(self.tree.find('FamilySelection'))
        self.plugins = NessusPluginList(self.tree.find('IndividualPluginSelection'))

        try:
            self.reports = map(lambda r:
                NessusReport(r),
                self.tree.findall('Report')
            )
        except ReportParserError,e:
            raise ReportParserError('Error parsing %s: %s' % (self.path,e))

    def __str__(self):
        return '%s: %d report' % (self.path,len(self.reports))

class NessusReportPreferences(object):
    def __init__(self,node):
        self.node = node

class NessusTargetFamilies(object):
    def __init__(self,node):
        self.node = node

class NessusPluginList(object):
    def __init__(self,node):
        self.node = node

class NessusReport(object):
    def __init__(self,node):
        self.node = node
        self.name = node.get('name')

        try:
            self.hosts = map(lambda h:
                NessusTargetHost(h),
                self.node.findall('ReportHost')
            )
        except ReportParserError,e:
            raise ReportParserError('Error parsing %s: %s' % (self.name,e))

    def __str__(self):
        return '%s: %d hosts' % (self.name,len(self.hosts))

class NessusTargetHost(list):
    def __init__(self,node):
        self.node = node
        self.name = node.get('name')
        if self.name is None:
            raise ReportParserError('No name')
        self.properties = NessusTargetHostProperties(node.find('HostProperties'))

        try:
            for i in self.node.findall('ReportItem'):
                self.append(NessusTargetResultItem(self,i))
        except ReportParserError,e:
            raise ReportParserError('Error parsing %s: %s' % (self.name,e))

    def __str__(self):
        return '%s %d results' % (self.name,len(self))

class NessusTargetHostProperties(dict):
    def __init__(self,node):
        self.node = node
        self.name = node.get('name')
        self.update(
            dict([(t.get('name').lower(),t.text) for t in node.getchildren()])
        ) 

    def __str__(self):
        if self.has_key('host_ip'):
            return '%s: %d properties' % (self['host-ip'],len(self.keys()))
        else:
            return '<NO IP> %d properties' % len(self.keys())

class NessusTargetResultItem(dict):
    def __init__(self,host,node):
        self.host = host
        self.node = node
        self.name = node.get('name')

        self.update(node.items())

        for k in ['port','severity','pluginID','bid']:
            if self.has_key(k):
                try:
                    self[k] = int(self[k])
                except ValueError:
                    raise ReportParserError('Error parsing %s: %s' % (k,self.details[k]))
        self.details = {}
        for n in node.getchildren():
            if self.details.has_key(n.tag):
                if type(self.details[n.tag]) != list:
                    self.details[n.tag] = [self.details[n.tag]]
                self.details[n.tag].append(n.text)
            else:
                self.details[n.tag] = n.text

        for k in ['description','plugin_output','solution','synopsis']:
            if self.details.has_key(k):
                self.details[k] = map(
                    lambda x: x.strip(),
                    self.details[k].split('\n')
                )
                if self.details[k] in [ [], [''], ['None'] ]:
                    self.details[k] = None

        if self.details.has_key('solution') and self.details['solution'] == ['n/a']:
            self.details['solution'] = None

        for k in ['port','severity','pluginID','bid']:
            if not self.details.has_key(k):
                continue
            values = self.details[k]
            if type(values) != list:
                values = [values]
            try:
                values = map(lambda x: int(x), values)
            except ValueError:
                raise ReportParserError('Error parsing %s: %s' % (k,self.details[k]))
            if len(values) == 1:
                values = values[0]
            self.details[k] = values

        for k in ['cvss_base_score','cvss_temporal_score']:
            if self.details.has_key(k):
                self.details[k] = decimal.Decimal(self.details[k])

        for k in [
                'plugin_modification_date',
                'plugin_publication_date',
                'vuln_publication_date',
                'patch_publication_date',
        ]:
            if self.details.has_key(k):
                dates = []
                for d in [d.strip() for d in self.details[k].split()]:
                    try:
                        dates.append(time.strptime(d,'%Y/%m/%d'))
                    except ValueError,e:
                        print '"%s"' % self.details[k]
                        raise ReportParserError('Error parsing dates for %s: %s %s' % (
                            k,self.details[k],e
                        ))
                self.details[k] = dates

        for k in ['exploit_available']:
            if not self.details.has_key(k):
                continue
            if self.details[k].lower() in ['true']:
                self.details[k] = True
            else:
                self.details[k] = False
                
        if self.details.has_key('plugin_version'):
            v = None
            for version_re in NESSUS_PLUGIN_REVISION_MATCHES:
                m = version_re.match(self.details['plugin_version'])
                if m:
                    v = m.group(1)
                    break
            if not v:
                raise ReportParserError('Error parsing plugin version: %s' % (
                    self.details['plugin_version']
                ))
            self.details['plugin_version'] = v

        if self.details.has_key('plugin_type'):
            if self.details['plugin_type'] not in NESSUS_PLUGIN_TYPES:
                raise ReportParserError('Unknown plugin type: %s' % (
                    self.details['plugin_type']
                ))

        if self.details.has_key('xref'):
            xrefs = []
            xref_urls = []

            entries = self.details['xref']
            if type(entries) != list:
                entries = [entries]
            for value in entries:
                try:
                    target,id = value.split(':',1)
                except ValueError:
                    raise ReportParserError('Error parsing xref: %s' % value)
                try:
                    xref_urls.append(XREF_URL_TEMPLATES[target] % {'id': id})
                except ValueError,e:
                    raise ReportParserError('Error parsing xref URL: %s' % e)
                except KeyError,e:
                    # No supported target URL mapping
                    pass
            self.details['xref_urls'] = xrefs

        for k in ['see_also','cve','xref']:
            if not self.details.has_key(k):
                continue
            if type(self.details[k]) != list:
                self.details[k] = [self.details[k]]

        if self.name is None:
            try:
                self.name = '%s %s %s' % (
                    self.host.name,self.port,self.protocol
                )
            except AttributeError,e:
                raise ReportParserError('Result: no name')

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError('No such attribute: %s' % attr)

    def __str__(self):
        details = self.details.items()
        if details == []:
            details = 'No details'
        return '%s: port %s severity %s %s' % (
            self.name,self.port,self.severity,details
        )

if __name__ == '__main__':
    for f in sys.argv[1:]:
        try:
            nms = NessusXMLReport(f)
            
            for r in nms.reports:
                print r
                for h in r.hosts:
                    print h
                    for r in h:
                        print r.items()
                        if len(r.details) == 0:
                            continue
                        print '\n'.join('%20s %s' % (k,v) for k,v in r.details.items())

        except ReportParserError,e:
            print e
            sys.exit(1)
            continue
    sys.exit(0)

    for host in nms.hosts:
        print '### %s' % host
        #print host.osinfo
        for address in host.addresses:
            print '%6s %s' % (address.addrtype,address.addr)
        for port in host.tcp_ports:
            print '  TCP %5d %s' % (port.portid,port.service)
        for port in host.udp_ports:
            print '  UDP %5d %s' % (port.portid,port.service)

