#!/usr/bin/env python
"""
Parser class for MBSA XML report files
"""

import os,sys,time
from lxml import etree

from scanreports import ReportParserError
from seine.address import IPv4Address,IPv6Address

GRADE_VALUE_DESCRIPTION_MAP = {
    1:      'High',
    2:      'Medium',
    3:      'Low',
    4:      'Info',
    5:      'Info',
}

class MBSAReport(dict):
    def __init__(self,path):
        self.path = path
        try:
            self.tree = etree.parse(self.path)  
        except etree.XMLSyntaxError,e:
            raise ReportParserError('Error parsing %s: %s' % (self.path,e))
        self.update(dict(self.tree.getroot().items()))

        self.checks = [MBSACheck(self,n) for n in self.tree.findall('Check')]
        self.checks.sort(lambda x,y: cmp(x.grade,y.grade))

    def __str__(self):
        return '%s\t%s' % (self.ipv4address.ipaddress,self.DisplayName)

    def __getattr__(self,attr):
        if attr == 'ipv4address':
            try:
                return IPv4Address(self.IP)
            except ValueError:
                raise ValueError('Invalid IP address: %s' % self.IP)
        try:
            return self[attr]
        except KeyError:
            pass
        raise AttributeError

class MBSACheck(dict):
    def __init__(self,tree,node):
        self.tree = tree
        self.node = node
        for k,v in self.node.items():
            self[k.lower()] = v
        for k in ['grade','rank','cat','type','id']:
            try:
                self[k] = int(self[k])
            except KeyError:
                continue
            except ValueError:
                raise ValueError('Invalid value for %s: %s' % (k,self[k]))
        self.advice = [MBSAAdvice(self,n) for n in self.node.findall('Advice')]
        self.detail = [MBSACheckDetail(self,n) for n in self.node.findall('Detail')]

    def __str__(self):
        try:
            grade_description = GRADE_VALUE_DESCRIPTION_MAP[self.grade]
        except KeyError:
            grade_description = GRADE_VALUE_DESCRIPTION_MAP[5]
        return '%s\t%s' % (grade_description,self.name)

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            pass
        raise AttributeError

class MBSAAdvice(dict):
    def __init__(self,check,node):
        self.check = check
        self.node = node

        for k,v in self.node.items():
            self[k.lower()] = v

    def __str__(self):
        return self.node.text

class MBSACheckDetail(dict):
    def __init__(self,check,node):
        self.check = check
        self.node = node
        for k,v in self.node.items():
            self[k.lower()] = v
    
        try:
            self.rows = []
            self.columns = [col.text for col in self.node.find('Head').findall('Col')]  
            for r in self.node.findall('Row'):
                row = {}
                for i,col in enumerate(r.findall('Col')):
                    value = col.text
                    if value == '-': 
                        value = None
                    row[self.columns[i]] = value
                self.rows.append(row)
            self.updates = []
        except AttributeError,e:  
            self.columns = []
            self.rows = []
            if self.node.find('UpdateData') is not None:
                self.updates = [MBSAUpdateData(self,n) for n in self.node.findall('UpdateData')]

class MBSAUpdateData(dict):
    def __init__(self,detail,node):
        self.detail = detail
        self.node = node
        for k,v in self.node.items():
            self[k.lower()] = v
        for k in ['isinstalled','restartrequired']:
            try:
                self[k] = self[k] != 'false' and True or False
            except KeyError:
                pass
        for k in ['kbid','type','severity']:
            try:
                self[k] = int(self[k])
            except KeyError:
                pass
        
        self['title'] = self.node.find('Title').text

    def __getattr__(self,attr):
        try:
            return self[attr]
        except KeyError:
            pass
        raise AttributeError('No such attribute: %s' % attr)

    def __str__(self):
        return '%-8s\t%s' % (self.id,self.title)

if __name__ == '__main__':
    import sys
    reports = []
    for path in sys.argv[1:]:
        reports.append(MBSAReport(path))
    reports.sort(lambda x,y: cmp(x.ipv4address.address,y.ipv4address.address))
    
    for report in reports:
        print '\n%s' % report
        for c in filter(lambda r: r.grade<=3, report.checks):
            if c.name == 'IIS Status': continue
            print c
            for a in c.advice:
                print '\t%s' % a
            for d in c.detail:
                updates = filter(lambda u: u.isinstalled==False, d.updates)
                if len(updates)>0:
                    for u in updates:
                        print '\t',u
                #if d.rows != []:
                #    for row in d.rows:
                #        print '\t%s' % '\t'.join('%s:%s'%(k,v) for k,v in row.items())
