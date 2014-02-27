# -*- coding: utf-8 -*-
# this file is released under public domain and you can use without limitations

#########################################################################
## Customize your APP title, subtitle and menus here
#########################################################################

response.logo = A(B('XNC',XML('&trade;&nbsp;'),SPAN('Monitor')),
                  _class="brand",_href="http://www.cisco.com/go/xnc")
response.title = 'XNC Monitor' + '--' + request.function
response.subtitle = 'Client'

## read more at http://dev.w3.org/html5/markup/meta.name.html
response.meta.author = 'Tong Zhu <zhtong@cisco.com>'
response.meta.description = 'XNC Monitor Manager Clinet Application'
response.meta.keywords = 'XNC Monitor'
response.meta.generator = 'Web2py Web Framework'


#########################################################################
## this is the main application menu add/remove items as required
#########################################################################

response.menu = [
    (I(_class='icon-home icon-large'), False, URL('index'), []),
    (SPAN(T('Provision')), False, None, [
        (T('Application/Conversation'), False, URL('select_app'), []),
        (T('Rule'), False, URL('select_ruleset'), []),
        (T('IP & Port'), False, URL('input5tuple'), []),
    ]),
    (SPAN(T('Configuration')), False, None, [
        (T('Application/Conversation'), False, URL('app_pair'), []),
        (T('Filter/Rule'), False, URL('policy'), []),
        (T('XNC Configuration'), False, URL('xnc_config'), []),
    ]),
]

if request.is_local:
    response.menu.append((T('Admin'), False, '/admin/default/site', []))

DEVELOPMENT_MENU = True

#########################################################################
## provide shortcuts for development. remove in production
#########################################################################

def _():
    # shortcuts
    app = request.application
    ctr = request.controller
    # useful links to internal and external resources
if DEVELOPMENT_MENU: _()

if "auth" in locals(): auth.wikimenu() 
