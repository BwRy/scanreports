#!/usr/bin/env python
"""
Parser for nessus XML report files
"""

import os,logging,sys,time,re,decimal
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

REPORT_TEXT_VALUES = ['description','plugin_output','synopsis']
REPORT_INT_VALUES = ['port','severity','pluginID','bid']
REPORT_BOOLEAN_VALUES = [
    'exploit_available',
    'exploit_framework_metasploit',
    'exploit_framework_canvas',
    'exploit_framework_core',
]
REPORT_REFERENCE_FIELDS = ['cve','cpe','xref','see_also']
REPORT_DECIMAL_VALUES = ['cvss_base_score','cvss_temporal_score']
REPORT_DATE_VALUES = [ 
    'plugin_modification_date', 
    'plugin_publication_date', 
    'vuln_publication_date', 
    'patch_publication_date'
]
REPORT_SINGLE_STRING_VALUES = [
    'cvss_vector',
    'cvss_temporal_vector',
    'exploitability_ease',
    'metasploit_name',
    'canvas_package',
]

class NessusXMLReport(list):
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

        for node in self.tree.findall('Report'):
            # May raise ReportParserError 
            self.append(NessusReport(self,node))

    def __str__(self):
        return '%s: %d reports' % (self.path,len(self))

class NessusReport(list):
    def __init__(self,master,node):
        self.master = master
        self.node = node
        self.name = node.get('name')

        for node in self.node.findall('ReportHost'):
            # May raise ReportParserError
            self.append(NessusTargetHost(self,node))

    def __str__(self):
        return '%s: %d hosts' % (self.name,len(self))

class NessusTargetHost(list):
    def __init__(self,report,node):
        self.report = report
        self.node = node
        self.address = node.get('name')
        self.properties = NessusTargetHostProperties(node.find('HostProperties'))

        if self.address is None:
            raise ReportParserError('No address')
        try:
            self.address = IPv4Address(self.address)
        except ValueError:
            try:
                self.address = IPv6Address(self.address)
            except ValueError:
                raise ReportParserError(
                    'Error parsing name to address: %s' % self.name
                )

        try:
            for i in self.node.findall('ReportItem'):
                self.append(NessusTargetResultItem(self,i))
        except ReportParserError,e:
            raise ReportParserError('Error parsing %s: %s' % (self.address,e))

    def __str__(self):
        return '%s %d results' % (self.address,len(self))

class NessusTargetHostProperties(dict):
    def __init__(self,node):
        self.node = node
        self.name = node.get('name')
        self.update( dict(
            [(t.get('name').lower(),t.text) for t in node.getchildren()]
        )) 

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

        for k in filter(lambda k: self.has_key(k), REPORT_INT_VALUES):
            try:
                self[k] = int(self[k])
            except ValueError:
                raise ReportParserError('Invalid integer value: %s' % self[k])

        for n in node.getchildren():
            if n.tag in REPORT_INT_VALUES:
                try:
                   self[n.tag] = int(n.text)
                except ValueError:
                    raise ReportParserError('Invalid integer value %s: %s' %
                        n.tag,n.text
                    )
        
            elif n.tag in REPORT_DECIMAL_VALUES:
                try:
                    self[n.tag] = decimal.Decimal(n.text)
                except ValueError:
                    raise ReportParserError('Invalid decimal value %s: %s' % (
                        n.tag,n.text
                    ))

            elif n.tag in REPORT_TEXT_VALUES:
                self[n.tag] = []
                for l in n.text.split('\n'):
                    if l.strip() == '':
                        continue
                    self[n.tag].append(l)

            elif n.tag in REPORT_DATE_VALUES:
                dates = []
                for d in filter(lambda d: d.strip(), n.text.split()):
                    try:
                        dates.append(time.strptime(d,'%Y/%m/%d'))
                    except ValueError,e:
                        raise ReportParserError('Invalid date %s: %s' % (k,d))
                self[n.tag] = dates

            elif n.tag in REPORT_BOOLEAN_VALUES:
                if n.text.lower() in ['true','yes']:
                    self[n.tag] = True
                else:
                    self[n.tag] = False
                
            elif n.tag == 'plugin_version':
                plugin_version = None
                for rev in NESSUS_PLUGIN_REVISION_MATCHES:
                    m = rev.match(n.text)
                    if not m:
                        continue
                    plugin_version = m.group(1)
                    break
                if plugin_version is None:
                    raise ReportParserError('Unknown plugin version %s' % pv)
                self['plugin_version'] = plugin_version

            elif n.tag == 'plugin_type':
                if n.text not in NESSUS_PLUGIN_TYPES:
                    raise ReportParserError('Unknown plugin types: %s' % n.text)
                self[n.tag] = n.text

            elif n.tag == 'solution':
                if n.text.lower() in ['n/a','']:
                    self['solution'] = None
                else:
                    self['solution'] = n.text.replace('\n',' ')

            elif n.tag == 'risk_factor':
                if n.text in ['None','']:
                    self[n.tag] = None
                else:
                    self[n.tag] = n.text

            elif n.tag in REPORT_REFERENCE_FIELDS:
                if not self.has_key(n.tag):
                    self[n.tag] = []
                self[n.tag].append(n.text)

            elif n.tag in REPORT_SINGLE_STRING_VALUES:
                if self.has_key(n.tag):
                    raise ReportParserErro('Multiple targets for %s' % n.tag)
                self[n.tag] = n.text

            else:
                raise ReportParserError('Unprocessed report field %s: %s' % (
                    n.tag,n.text
                ))

        if self.has_key('xref'):
            xref_urls = []
            for value in self['xref']:
                try:
                    (target,id) = value.split(':',1)
                except ValueError:
                    raise ReportParserError('Error splitting xref: %s' % value)
                try:
                    xref_urls.append(XREF_URL_TEMPLATES[target] % {'id': id})
                except ValueError,e:
                    raise ReportParserError('Error parsing xref URL: %s' % e)
                except KeyError,e:
                    pass
            self['xref_urls'] = xref_urls

        if not self.has_key('address'):
            self['address'] = self.host.address

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError('No such attribute: %s' % attr)

    def __str__(self):
        return '%s: port %s severity %s' % (
            self.name,self.port,self.severity
        )

class NessusReportPreferences(object):
    def __init__(self,node):
        self.node = node

class NessusTargetFamilies(object):
    def __init__(self,node):
        self.node = node

class NessusPluginList(object):
    def __init__(self,node):
        self.node = node

class NessusResultSet(list):
    def __init__(self):
        self.log = logging.getLogger('modules')

    def __sortkeys__(self,*argv):
        return lambda mapping: tuple(-mapping[name[1:]] if name.startswith('-') else mapping[name] for name in argv)

    def load(self,reports):
        for source in reports:
            self.log.debug('Merging report: %s' % source)
            for r in [result for report in source for host in report for result in host]:
                self.append(r)

    def order_by(self,*argv):
        self.log.debug('Ordering results')
        decorated = [(
            [-result[k[1:]] if k.startswith('-') else result[k] for k in argv],
            index,
            result
        ) for index,result in enumerate(self)]
        decorated.sort()
        self.__delslice__(0,len(self))
        self.extend([d[-1] for d in decorated])

    def pluginid_hosts(self,pid):
        self.log.debug('Collecting target host addresses for plugin %s' % pid)
        return [h.ipaddress for h in sorted(
            set(r.address for r in self if r.pluginID == pid) 
        )]

    def filter(self,fn):
        self.log.debug('Filtering %d results' % len(self))
        total=len(self)
        processed=0
        for r in self:
            processed+=1
            if not fn(r): 
                self.remove(r)
            if processed%1000==0:
                self.log.debug('Processed: %d/%d results' % (processed,total))

    def counters(self):
        values = dict([(r,0) for r in range(0,4)]) 
        for r in self:
            values[r.severity] += 1
        return values

    def filter_pluginlist(self,path,filtered_ids):
        try:
            for l in open(path,'r').readlines():
                if l.startswith('#'): continue
                (pid,description) = l.strip().split(None,1)
                try:
                    filtered_ids.add(int(pid)) 
                except ValueError:
                    sys.exit(error('Invalid Plugin ID: %s' % pid))
        except IOError,(ecode,emsg):
            raise ReportParserError(
                'Error reading filtered plugin list file %s %s' % (
                opts.filter_plugins,emsg
            ))
        except OSError,(ecode,emsg):
            raise ReportParserError(
                'Error reading filtered plugin list file %s %s' % (
                opts.filter_plugins,emsg
            ))
        self.filter(lambda x: x.pluginID not in filtered_ids)

    def match_addresslist(self,values):
        self.log.debug('Matching address list to %s' % values)
        addresses = []
        for address in values:
            try:
                address = IPv4Address(address)  
            except ValueError:
                try:
                    address = IPv6Address(address)
                except ValueError:
                    raise ReportParserError('Invalid address: %s' % address)
            addresses.append(address)

        def match(address,addresses):
            if address in addresses:
                return True
            if type(address) in [IPv4Address,IPv6Address]:
                for m in addresses:
                    if m.addressInNetwork(address):
                        return True
            else:
                raise ReportParserError('Unknown address type: %s' % address)
            return False
        self.filter(lambda x: match(x.address,addresses))

if __name__ == '__main__':
    nms = NessusXMLReport(sys.argv[1])
    #nms.resultset.filter(lambda x: x.address == IPv4Address('10.0.0.52'))
    nms.resultset.order_by('address','-severity','port',)
    for r in nms.resultset:
        print r.severity,r.address.ipaddress,r.port
    print nms.resultset.counters()

