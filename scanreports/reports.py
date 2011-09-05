#!/usr/bin/env python
"""
Supported scan report output formats.
"""

import sys,os,logging
from configobj import ConfigObj

from scanreports import ReportParserError

DEFAULT_CONFIG_PATH = os.path.join(os.getenv('HOME'),'.scanreports.conf')
DEFAULT_CONFIG = {
    'header': { 'color': '#ffffff', 'background': '#0082C8' },
    'levels': {
        'High': { 'level':3, 'color':'#eeeeee', 'background':'#ff5050' },
        'Medium': { 'level':2, 'color':'#000000', 'background':'#ffb565' },
        'Low': { 'level':1, 'color':'#000000', 'background':'#fdff6b' },
        'Info': { 'level':0, 'color':'#000000', 'background':'#aaffaa' },
    }
}

DEFAULT_HTML_TEMPLATE = """<html>
<head><title>Nessus Report %(title)s</title></head>
<style type="text/css">
body { margin: 0; padding: 0 }
h3 { margin: 5px; padding: 0; }
table { margin: 5px; padding: 0; border-collapse: collapse; }
td { border: 1px solid black; vertical-align: top; }
td.filler { border: none; padding: 5px; }
th { border: 1px solid black; vertical-align: bottom; background-color: %(bg_header)s; color: %(fg_header)s; font-weight: bold; }
td.high { color: %(fg_high)s; background-color: %(bg_high)s; }
td.medium { color: %(fg_medium)s; background-color: %(bg_medium)s; }
td.low { color: %(fg_low)s; background-color: %(bg_low)s; }
td.info { color: %(fg_info)s; background-color: %(bg_info)s; }
</style>
</html>
<body>
<h3>%(format)s Report - %(title)s</h3>
<table>
%(table)s
</table>
</body>
</html>
"""

class ScanReportConfig(dict):
    def __init__(self,path=DEFAULT_CONFIG_PATH):
        self.path = path
        self.update(DEFAULT_CONFIG)
        self.update(ConfigObj(path))

    def __resolve_level(self,level):
        if level in self['levels'].keys():
            return level
        try:
            level = int(level)
            return filter(lambda l:
                level==self['levels'][l]['level'],
                self['levels'].keys()
            )[0]
        except IndexError:
            raise ReportParserError('Invalid level: %s' % level) 
        except ValueError:
            raise ReportParserError('Invalid level: %s' % level) 

    def name(self,level):
        return self.__resolve_level(level)

    def background(self,level):
        if level == 'header':
            return self['header']['background']
        level = self.__resolve_level(level)
        try:
            return self['levels'][level]['background']
        except KeyError:
            raise ReportParserError('No background defined for level %s' % level)

    def color(self,level):
        if level == 'header':
            return self['header']['color']
        level = self.__resolve_level(level)
        try:
            return self['levels'][level]['color']
        except KeyError:
            raise ReportParserError('No color defined for level %s' % level)

class ScanReport(list):
    def __init__(self,path=None,fileformat='text',config=None):
        self.path = path
        self.format = fileformat
        self.config = config is not None and config or ScanReportConfig()
        self.levels = sorted( self.config['levels'].keys(), lambda x,y: 
            cmp(self.config['levels'][y]['level'],self.config['levels'][x]['level'])
        )
        self.reportformat = 'Unknown'
        self.title = 'Report Title'

    def header(self,label,value=None):
        self.append('%s %s' % (label,value))
        return

    def row(self,severity,label,fields):
        self.append('%s %s' % (label,' '.join('%s:%s'%(k,v) for k,v in fields)))

    def write(self,path=None):
        if path is not None:
            self.path = path
        sys.stdout.write('%s\n' % '\n'.join(self))

class CSVReport(ScanReport):
    def __init__(self,path=None,config=None,delimiter='\t'):
        ScanReport.__init__(self,path,fileformat='csv',config=config)
        self.delimiter = delimiter

    def header(self,label,value=None):
        if value is not None:
            self.append([label,value])
        else:
            self.append(label)

    def row(self,severity,label,fields):
        self.append([label] + list(fields))

    def write(self,path=None):
        import csv
        if path is not None:
            self.path = path
        writer = csv.writer(open(self.path,'w'),delimiter=self.delimiter)
        writer.writerows(self)

class HTMLReport(ScanReport):
    def __init__(self,path=None,config=None,template=DEFAULT_HTML_TEMPLATE):
        ScanReport.__init__(self,path,fileformat='html',config=config)
        self.template = template

    def header(self,label,value=None):
        if len(self)>0:
            self.append('<tr><td class="filler">&nbsp;</td></tr>')
        if value is not None:
            self.append("""<tr><th>%s</th><th>%s</th></tr>""" % (label,value))
        else:
            self.append("""<tr><th colspan="2">%s</th></tr>""" % (label))

    def row(self,severity,label,fields):
        if severity is not None and label is not None:
            self.append("""<tr><td class="%s">%s</td>%s</tr>""" % (
                severity.lower(),
                label,
                ''.join("""<td>%s</td>"""% f for f in fields)
            ))
        else:
            self.append("""<tr>%s</tr>""" % 
                ''.join("""<td>%s</td>"""% f for f in fields)
            )

    def write(self):
        fd = open(self.path,'w')
        fd.write('%s\n' % self.template % {
            'title': self.title,
            'format': self.reportformat,
            'table': '\n'.join(self),
            'bg_header': self.config.background('header'),
            'fg_header': self.config.color('header'),
            'bg_high': self.config.background('High'),
            'fg_high': self.config.color('High'),
            'bg_medium': self.config.background('Medium'),
            'fg_medium': self.config.color('Medium'),
            'bg_low': self.config.background('Low'),
            'fg_low': self.config.color('Low'),
            'bg_info': self.config.background('Info'),
            'fg_info': self.config.color('Info'),
        })
        fd.close()

class ODFReport(ScanReport):
    def __init__(self,path=None,config=None):
        ScanReport.__init__(self,path,fileformat='odf',config=config)

if __name__ == '__main__':
    r = HTMLReport(sys.argv[1])
    r.header('Test1','Test')
    r.reportformat = 'Test'
    r.title = 'Testing report generation'
    for i,s in enumerate(r.levels):
        r.row(severity=s,label='Row %d'%i,fields=('field 1','field 2','field 3'))
    r.header('Test2','Test')
    for i,s in enumerate(r.levels):
        r.row(severity=s,label='Row %d'%i,fields=('field 1','field 2','field 3'))
    r.write()

