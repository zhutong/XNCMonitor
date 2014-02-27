# -*- coding: utf-8 -*-

#########################################################################
## This scaffolding model makes your app work on Google App Engine too
## File is released under public domain and you can use without limitations
#########################################################################

## if SSL/HTTPS is properly configured and you want all HTTP requests to
## be redirected to HTTPS, uncomment the line below:
# request.requires_https()

if not request.env.web2py_runtime_gae:
    ## if NOT running on Google App Engine use SQLite or other DB
    db = DAL('sqlite://storage.sqlite',pool_size=1,check_reserved=['all'])
else:
    ## connect to Google BigTable (optional 'google:datastore://namespace')
    db = DAL('google:datastore')
    ## store sessions and tickets there
    session.connect(request, response, db=db)
    ## or store session in Memcache, Redis, etc.
    ## from gluon.contrib.memdb import MEMDB
    ## from google.appengine.api.memcache import Client
    ## session.connect(request, response, db = MEMDB(Client()))

## by default give a view/generic.extension to all actions from localhost
## none otherwise. a pattern can be 'controller/function.extension'
response.generic_patterns = ['*'] if request.is_local else []
## (optional) optimize handling of static files
# response.optimize_css = 'concat,minify,inline'
# response.optimize_js = 'concat,minify,inline'
## (optional) static assets folder versioning
# response.static_version = '0.0.0'
#########################################################################
## Here is sample code if you need for
## - email capabilities
## - authentication (registration, login, logout, ... )
## - authorization (role based authorization)
## - services (xml, csv, json, xmlrpc, jsonrpc, amf, rss)
## - old style crud actions
## (more options discussed in gluon/tools.py)
#########################################################################

from gluon.tools import Auth, Crud, Service, PluginManager, prettydate
auth = Auth(db)
crud, service, plugins = Crud(db), Service(), PluginManager()

## create all tables needed by auth if not custom tables
auth.define_tables(username=False, signature=False)

## configure email
mail = auth.settings.mailer
mail.settings.server = 'logging' or 'smtp.gmail.com:587'
mail.settings.sender = 'you@gmail.com'
mail.settings.login = 'username:password'

## configure auth policy
auth.settings.registration_requires_verification = False
auth.settings.registration_requires_approval = False
auth.settings.reset_password_requires_verification = True

## if you need to use OpenID, Facebook, MySpace, Twitter, Linkedin, etc.
## register with janrain.com, write your domain:api_key in private/janrain.key
from gluon.contrib.login_methods.rpx_account import use_janrain
use_janrain(auth, filename='private/janrain.key')

db.define_table('monitor_app',
  Field('name','string',length=128,required=True,unique=True),
  Field('description','text'),
  format = '%(name)s'
  )
#db.post.image_id.writable = db.post.image_id.readable = False

db.define_table('monitor_switch',
  Field('name','string',length=128,required=True,unique=True),
  Field('switch_id','string',length=25,required=True,unique=True),
  Field('switch_type','string',length=20,default='OF'),
  Field('description','text'),
  format = '%(name)s'
  )

db.define_table('monitor_port',
  Field('name','string',length=128,required=True,unique=True),
  Field('monitor_switch_id', 'reference monitor_switch',required=True),
  Field('port_id','string',length=25, required=True),
  Field('port_type','list:string',default='Edge-SPAN'),
  Field('description','text'),
  format = '%(name)s'
  )
db.monitor_port.port_type.requires=IS_IN_SET(('Edge-SPAN','Edge-TAP','Delivery'))

db.define_table('monitor_pair',
  Field('name','string',length=128,required=True,unique=True),
  Field('src_ip','string',length=18,label='Source IP Address'),
  Field('dst_ip','string',length=18,label='Destination IP Address'),
  Field('protocol','string',default='6'),
  Field('src_port','string',label='Source Port'),
  Field('dst_port','string',label='Destination Port'),
  Field('apps','list:reference monitor_app',label='Mapped Applications'),
  Field('span_ports','list:reference monitor_port',label='Monitor Sources'),
  Field('description','text'),
  format = '%(name)s'
  )

db.define_table('monitor_device',
  Field('name','string',length=128,required=True,unique=True),
  Field('monitor_port_id','reference monitor_port',required=True),
  Field('description','text'),
  format = '%(name)s'
  )

db.define_table('monitor_filter',
  Field('name','string',length=128,required=True,unique=True),
  Field('priority','string',default='500'),
  Field('vlanId','string'),
  Field('vlanPriority','string'),
  Field('datalayerSrc','string',length=18,label='Source MAC Address'),
  Field('datalayerDst','string',length=18,label='Destination MAC Address'),
  Field('etherType','string',default='0x0800'),
  Field('networkSrc','string',length=18,label='Source IP Address'),
  Field('networkDst','string',length=18,label='Destination IP Address'),
  Field('protocol','string',default='6'),
  Field('tosBits','string'),
  Field('transportPortSrc','string',label='Source Port'),
  Field('transportPortDst','string',label='Destination Port'),
  Field('vlanToSet','string'),
  Field('description','text'),
  Field('monitor_pair_id','reference monitor_pair'),
  format = '%(name)s'
  )

db.define_table('monitor_rule',
  Field('name','string',length=128,required=True,unique=True),
  Field('monitor_filter', 'string', required=True),
  Field('sourcePort',label='Source Monitor Port'),
  Field('device', 'string', required=True, label='Destination Monitor Devices'),
  Field('description','text'),
  format = '%(name)s'
  )

db.define_table('monitor_ruleset',
  Field('name','string',length=128,required=True,unique=True),
  Field('rules','list:reference monitor_rule',required=True),
  Field('description','text',required=True),
  format = '%(name)s'
  )
