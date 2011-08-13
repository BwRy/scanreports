
from lxml import etree

from scanreports import ReportParserError
from seine.address import IPv4Address,IPv6Address

class NMAPXMLOutputFile(object):
    def __init__(self,path):
        self.path = path
        try:
            self.tree = etree.parse(self.path)
        except etree.XMLSyntaxError,e:
            raise ReportParserError('Error parsing %s: %s' % (self.path,e))

        root = self.tree.getroot()
        if root.tag != 'nmaprun':
            raise ReportParserError('Input is not supported NMAP XML output file') 
        self.scanner = root.get('scanner') 
        self.version = root.get('version') 
        self.args = root.get('args') 
        self.start_ts = int(root.get('start'))
        self.scaninfo = NMAPScanInfo(self.tree.find('scaninfo'))
        self.runstats = NMAPRunStats(self.tree.find('runstats'))

        try:
            self.hosts = map(lambda h:
                NMAPTargetHostEntry(h),
                self.tree.findall('host')
            )
        except ReportParserError,e:
            raise ReportParserError('Error parsing %s: %s' % (self.path,e))

    def __str__(self):
        return '%s (%s at %s)' % (
            self.path,
            self.args,
            time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(self.start_ts)),
        )

class NMAPTargetHostEntry(object):
    def __init__(self,node):
        self.nmapscans = [ NMAPHostScan(node) ]
        self.ports = map(lambda p: 
            NMAPTargetPortEntry(p),
            node.find('ports').findall('port'),
        )
        self.addresses = map(lambda a:
            NMAPHostAddressEntry(a),
            node.findall('address'),
        )
        self.osinfo = NMAPHostOSGuesses(node.find('os'))

    def __getattr__(self,attr):
        if attr == 'ipv4_addresses':
            return filter(lambda a: a['addrtype'] == 'ipv4', self.addresses)
        if attr == 'mac_addresses':
            return filter(lambda a: a['addrtype'] == 'mac', self.addresses)
        if attr == 'udp_ports':
            return filter(lambda p: p['protocol'] == 'udp', self.ports)
        if attr == 'tcp_ports':
            return filter(lambda p: p['protocol'] == 'tcp', self.ports)
        if attr == 'os':
            if len(self.osinfo) == 1:
                osc = self.osinfo[0]
                fields = filter(lambda x: x!='accuracy', osc.keys())
                return '%s' % ','.join(['%s:%s' % (k,osc[k]) for k in fields])
            else:
                return 'UNKNOWN: %d OS matches' % len(self.osinfo)
        raise AttributeError('No such NMAPTargetHostEntry attribute: %s' % attr)

    def __str__(self):
        return '%s %d ports detected (%s)' % (
            self.ipv4_addresses[0], len(self.ports), self.os,
        )

    def merge(self,host):
        for run in self.nmapscans:
            for newrun in host.nmapscans:
                if newrun.start_ts == run.start_ts and newrun.end_ts == run.end_ts:
                    return
        self.nmapscans += host.nmapscans
        self.ports += host.ports
        for k in ['ipv4','ipv6','mac']:
            my_values = filter(lambda a: a['addrtype']==k, self.addresses)
            host_values = filter(lambda a: a['addrtype']==k, host.addresses)
            for a in host_values:
                matches = filter(lambda x: a['addr'] == x['addr'], my_values)
                if len(matches) == 0:
                    self.addresses.append(a)
                    break

class NMAPHostScan(object):
    def __init__(self,node):
        if node.get('starttime') is None:
            raise ReportParserError('No start time in node')
        self.start_ts = int(node.get('starttime'))
        self.end_ts   = int(node.get('endtime'))
        self.state    = node.find('status').get('state')
        self.reason   = node.find('status').get('reason')

    def __str__(self):
        return '%s %s' % (self.state,self.reason)

class NMAPHostOSGuesses(list):
    def __init__(self,node):
        try:
            for osc in map(lambda osc: dict(osc.items()), node.findall('osclass'),):
                self.append(osc)
        except AttributeError:
            return

        try:
            self.fingerprint = node.find('osfingerprint').get('fingerprint')
        except AttributeError:
            self.fingerprint = None

    def __str__(self):
        if len(self) == 1:
            m = self[0]
            return ', '.join('%s:%s' % (k,m[k]) for k in m.keys())
        else:
            return 'Not certain: %d OS matches' % ( len(self.matches) )

class NMAPHostAddressEntry(dict):
    def __init__(self,node):
        self.update(node.items())

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError

    def __str__(self):
        return '%s %s' % (self['addrtype'],self['addr'])

class NMAPTargetPortEntry(dict):
    def __init__(self,node):
        self['protocol'] = node.get('protocol')
        self['portid']   = int(node.get('portid'))
        try:
            self['service'] = NMAPTargetServiceEntry(node.find('service'))
        except AttributeError:
            self['service'] = None
        self.update(node.find('state').items())

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError

    def __int__(self):
        return self['portid']

    def __str__(self):
        return ', '.join('%s:%s' % (k,self[k]) for k in self.keys())

class NMAPTargetServiceEntry(dict):
    def __init__(self,node):
        self.update(node.items())

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError

    def __str__(self):
        return self['name']
    
class NMAPRunStats(dict):
    def __init__(self,node):
        self.finished = dict(node.find('finished').items())
        self.hosts = dict(node.find('hosts').items())
        for k in self.hosts.keys():
            try:
                self.hosts[k] = int(self.hosts[k])
            except ValueError:
                raise ReportParserError('Runstats hosts attribute %s not integer' % k)

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError

    def __str__(self):
        return '%s seconds %d up %d down %d total' % (
            self.finished['elapsed'],
            self.hosts['up'],
            self.hosts['down'],
            self.hosts['total'],
        )

class NMAPScanInfo(dict):
    def __init__(self,node):
        self.update(node.items())   
        if self.has_key('numservices'):
            self['numservices'] = int(self['numservices'])
        if self.has_key('services'):
            services = []
            try:
                service_list = self['services'].split(',')
                for s in service_list: 
                    try:
                        start,end = map(lambda x: int(x), s.split('-'))
                        for i in range(start,end+1):
                            services.append(i)
                    except ValueError:
                        try:
                            services.append(int(s))
                        except ValueError:
                            raise ValueError
            except ValueError:
                raise ReportParserError('Error parsing services: %s' % self['services'])
            self['services'] = services

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError

    def __str__(self):
        return 'Scanned %s %s %d services' % (
            self['type'],self['protocol'],self['numservices']
        )

def same_target(a,b):
    for k in ['ipv4','ipv6','mac']:
        a_values = filter(lambda a: a['addrtype']==k, a.addresses)
        b_values = filter(lambda a: a['addrtype']==k, b.addresses)
        for a_addr in a_values:
            for b_addr in b_values:
                if a_addr['addr'] == b_addr['addr']:
                    return True
    return False

class NMAPSummary(object):
    def __init__(self):
        self.files = []
        self.hosts = [] 

    def __str__(self):
        return '%d unique hosts from %d files' % (
            len(self.hosts), len(self.files)
        )

    def find_host(self,host):
        for h in self.hosts:
            if same_target(host,h):
                return h 
        return None 

    def read(self,path):
        try:
            entry = NMAPXMLOutputFile(path)
        except ReportParserError,e:
            raise ReportParserError(e)

        self.files.append(entry)
        for h in entry.hosts:
            host = self.find_host(h)
            if not host:
                self.hosts.append(h)
                continue
            # Merge details of hosts
            host.merge(h)    

        self.hosts.sort(lambda y,x: cmp(
            IPv4Address(y.addresses[0]['addr']).address,
            IPv4Address(x.addresses[0]['addr']).address,
        ))

if __name__ == '__main__':
    nms = NMAPSummary()
    for f in sys.argv[1:]:
        try:
            nms.read(f)
        except ReportParserError,e:
            print e
            continue

    print nms 

    for host in nms.hosts:
        print '### %s' % host
        for address in host.addresses:
            print '%6s %s' % (address.addrtype,address.addr)
        for port in host.tcp_ports:
            print '  TCP %5d %s' % (port.portid,port.service)
        for port in host.udp_ports:
            print '  UDP %5d %s' % (port.portid,port.service)

