#!/usr/bin/env python
"""
Parser for nipper (commercial version) HTML reports
"""

import os,logging,sys,time,re

from scanreports import ReportParserError
from BeautifulSoup import BeautifulSoup

DEVICE_TITLES = [
    re.compile('^(Juniper NetScreen) (.*) Security Report$'),
    re.compile('^(Cisco PIX Security Appliance) (.*) Security Report$'),
    re.compile('^(Cisco Router) (.*) Security Report$'),
    re.compile('^(Cisco Catalyst) (.*) Security Report$'),
]

SKIP_DIVS = [
    'frontpage','contents','tableindex','about','security','appendix',
    'GEN.SECINTRO.1', 'GEN.SECCONCL.1', 'GEN.SECRECOM.1',
    'ABOUTREPORTORGANISATION','ABOUTREPORTCONVENTIONS',
    'APPENDIX-ABBREV','APPENDIX-PORTS','APPENDIX-PROTOCOLS',
    'APPENDIX-ICMPTYPES','APPENDIX-NIPPERVER',
]

SEVERITY_MAP = {
    'High':     ['high','critical'],
    'Medium':   ['medium'],
    'Low':      ['low'],
    'Info':     ['info','informational'],
}

SUMMARY_TEXT_FIELD_NAMES = ['impact','ease']
ISSUE_TEXT_FIELD_NAMES = ['finding','impact','ease','recommendation']

RE_ISSUE_HEADER = re.compile('^[0-9.]+\s+(.*)$')

class NipperCommercialHTMLReport(dict):
    def __init__(self,path):
        self.path = path
        self.update(dict((k,{}) for k in SEVERITY_MAP.keys()))

        if not os.path.isfile(self.path):
            raise ReportParserError('No such file: %s' % self.path)
        self.parser = BeautifulSoup(markup=open(self.path,'r').read())

        contents = self.parser.find('div',{'id':'contents'})
        if contents is None:
            raise ReportParserError('No table of contents found')

        self.device = None
        self.name = None
        t = self.parser.find('title').text
        for re_match in DEVICE_TITLES:
            m = re_match.match(t)  
            if m:
                self.device = m.group(1)
                self.name = m.group(2)
                break

        if self.device is None or self.name is None:
            raise ReportParserError('Could not parse device type and name')

        for d in self.parser.findChildren('div'):
            d_id = d.get('id')
            if d_id is None or d_id in SKIP_DIVS:
                continue
            r = NipperReportedIssue(self,d)
            try:
                severity = filter(lambda k: 
                    r.severity in SEVERITY_MAP[k],
                    SEVERITY_MAP.keys()
                )[0]
            except IndexError:
                ReportParserError('Unknown severity level: %s' % r.severity)
            if not self[severity].has_key(r.issue):
                self[severity][r.issue] = []
            self[severity][r.issue].append(r) 

    def __repr__(self):
        return self.path

class NipperReportedIssue(dict):
    def __init__(self,report,section):
        self.report = report
        m = RE_ISSUE_HEADER.match(section.find('h3').text)
        if not m:
            raise ReportParserError('Could not parse report h3 header: %s' % section)
        self.issue = m.group(1)
        
        for sub in section.findChildren('div'):
            sub_id = sub.get('class')
            if sub_id == 'ratings':
                self['severity'] = NipperIssueRatings(sub)
            elif sub_id == 'finding':
                self['finding'] = NipperIssueFinding(sub)
            elif sub_id == 'impact':
                self['impoct'] = NipperIssueImpact(sub)
            elif sub_id == 'ease':
                self['ease'] = NipperIssueEase(sub)
            elif sub_id == 'recommendation':
                self['recommendation'] = NipperIssueRecommendation(sub)
            else:
                print sub_id

    def __getattr__(self,attr):
        if attr in ['device','name']:
            return getattr(self.report,attr)
        if attr == 'severity':
            try:
                return self['severity'].value
            except KeyError:
                return 'unknown'
        raise AttributeError

    def __unicode__(self):
        return unicode(self.issue)

class NipperIssueRatings(object):
    def __init__(self,section):
        self.label = 'Severity'

        n = section.find('font',{'class':'overallrating'})
        self.value = n.find('font').get('class')

    def __unicode__(self):
        return unicode(self.value)

class NipperIssueFinding(list):
    def __init__(self,section):
        self.label = 'Description'
        for p in section.findChildren('p'):
            self.append(p.text)

    def __unicode__(self):
        return unicode('\n'.join(self))

class NipperIssueEase(list):
    def __init__(self,section):
        self.label = 'Exploitability'
        for p in section.findChildren('p'):
            self.append(p.text)

    def __unicode__(self):
        return unicode('\n'.join(self))

class NipperIssueImpact(list):
    def __init__(self,section):
        self.label = 'Impact'
        for p in section.findChildren('p'):
            self.append(p.text)

    def __unicode__(self):
        return unicode('\n'.join(self))

class NipperIssueRecommendation(list):
    def __init__(self,section):
        self.label = 'Recommendation'
        for p in section.findChildren('p'):
            self.append(p.text)

    def __unicode__(self):
        return unicode('\n'.join(self))

class NipperReportsSummary(dict):
    def __init__(self):
        self.update(dict((k,{}) for k in SEVERITY_MAP.keys()))
        self.log = logging.getLogger('modules')

    def load(self,path):
        self.log.debug('Loading: %s' % path)
        r = NipperCommercialHTMLReport(path)
        for severity in SEVERITY_MAP.keys():
            for name,issues in r[severity].items():
                if not self[severity].has_key(name):
                    self[severity][name] = []
                self[severity][name].extend(r[severity][name])

    def __unicode__(self):
        return unicode('\n'.join(self))

