# -*- coding: utf-8 -*-


def index():
    """
    example action using the internationalization operator T and flash
    rendered by views/default/index.html or views/generic.html

    if you need a simple wiki simply replace the two lines below with:
    return auth.wiki()
    """
    return dict()


def user():
    """
    exposes:
    http://..../[app]/default/user/login
    http://..../[app]/default/user/logout
    http://..../[app]/default/user/register
    http://..../[app]/default/user/profile
    http://..../[app]/default/user/retrieve_password
    http://..../[app]/default/user/change_password
    http://..../[app]/default/user/manage_users (requires membership in
    use @auth.requires_login()
        @auth.requires_membership('group name')
        @auth.requires_permission('read','table name',record_id)
    to decorate functions that need access control
    """
    return dict(form=auth())


@cache.action()
def download():
    """
    allows downloading of uploaded files
    http://..../[app]/default/download/[filename]
    """
    return response.download(request, db)


def call():
    """
    exposes services. for example:
    http://..../[app]/default/call/jsonrpc
    decorate with @services.jsonrpc the functions to expose
    supports xml, json, xmlrpc, jsonrpc, amfrpc, rss, csv
    """
    return service()


#@auth.requires_signature()
def data():
    """
    http://..../[app]/default/data/tables
    http://..../[app]/default/data/create/[table]
    http://..../[app]/default/data/read/[table]/[id]
    http://..../[app]/default/data/update/[table]/[id]
    http://..../[app]/default/data/delete/[table]/[id]
    http://..../[app]/default/data/select/[table]
    http://..../[app]/default/data/search/[table]
    but URLs must be signed, i.e. linked with
      A('table',_href=URL('data/tables',user_signature=True))
    or with the signed load operator
      LOAD('default','data.load',args='tables',ajax=True,user_signature=True)
    """
    return dict(form=crud())


import xnc_rest


def __get_xnc():
    xnc = xnc_rest.XNCRest(**__get_xnc_access_method())
    return xnc


def __get_xnc_access_method():
    if session.xnc_access:
        return session.xnc_access
    try:
        import os, json

        f = os.path.join(request.folder, 'xnc_access.json')
        xnc_access = json.loads(open(f).read())
    except:
        xnc_access = dict(base_url='127.0.0.1:8080', username='admin', password='admin')
    session.xnc_access = xnc_access
    return xnc_access


def set_xnc():
    errorinfo = None
    xnc_access = __get_xnc_access_method()
    form = SQLFORM.factory(
        Field('url', default=xnc_access['base_url'], label='XNC URL', requires=IS_NOT_EMPTY()),
        Field('username', default=xnc_access['username'], requires=IS_NOT_EMPTY()),
        Field('password', 'password', requires=IS_NOT_EMPTY()),
        Field('verify', 'boolean'),
    )
    if form.process(keepvalues=True).accepted:
        xnc_access = {'base_url': form.vars.url,
                      'username': form.vars.username,
                      'password': form.vars.password,
        }
        response.flash = ''
        if form.vars.verify:
            try:
                xnc = xnc_rest.XNCRest(**xnc_access)
                if 'Error' in xnc.loginTest():
                    errorinfo = 'Login XNC Fail.'
            except:
                errorinfo = 'Login XNC Fail.'
        if not errorinfo:
            session.xnc_access = xnc_access
            import os, json

            f = os.path.join(request.folder, 'xnc_access.json')
            open(f, 'w').write(json.dumps(xnc_access))
    return dict(form=form, errorinfo=errorinfo, verify=form.vars.verify)


def xnc_config():
    if session.need_refresh_xnc:
        xnc_info = __get_xnc().refreshMonitor(temp_file_folder=request.folder)
        __update_db(xnc_info)
        del session.need_refresh_xnc
    else:
        xnc_info = xnc_rest.getDataset(temp_file_folder=request.folder)
    return xnc_info


def xnc_refresh():
    try:
        xnc_info = __get_xnc().refreshMonitor(temp_file_folder=request.folder)
        __update_db(xnc_info)
    except Exception as e:
        return str(e)
    try:
        del session.need_refresh_xnc
    except:
        pass
    return 'Refresh successfully.'


def __update_db(xnc_info):
    pass

#############################################     
ip_protocol = {1: 'ICMP(1)',
               2: 'IGMP(2)',
               4: 'IPv4(4)',
               6: 'TCP(6)',
               17: 'UDP(17)',
               47: 'GRE(47)',
               50: 'ESP(50)',
               51: 'AH(51)',
               88: 'EIGRP(88)',
               89: 'OSPF(89)',
}
ports = {20: 'FTP(20)',
         21: 'FTP(21)',
         22: 'SSH(22)',
         23: 'TELNET(23)',
         80: 'HTTP(80)',
         443: 'HTTPS(443)',
}


def app_pair():
    '''List all Application % Pairs'''
    return dict()


def app_pair_data():
    apps = db(db.monitor_app).select().as_list()
    pairs = db(db.monitor_pair).select().as_list()
    span_ports = db(db.monitor_port).select().as_list()
    return dict(apps=apps,
                pairs=pairs,
                protocols=ip_protocol,
                ports=ports,
                span_ports=span_ports)


def app():
    record = db.monitor_app(request.args(0))
    pairs = db(db.monitor_pair.apps.contains(record.id)).select()
    return dict(app=record, pairs=pairs)


def pair():
    record = db.monitor_pair(request.args(0))
    apps = db.monitor_pair.apps.represent(record.apps).split(',')
    return dict(p=record, apps=apps)


def policy():
    '''List all Filters & Rules'''
    filters = db(db.monitor_filter).select()
    rules = db(db.monitor_rule).select()
    rs = db.monitor_ruleset
    rulesets = db(rs).select()
    rule_dict = {}
    for r in rules:
        rule_dict[r.id] = r.name
    return dict(filters=filters, rules=rules, rulesets=rulesets, rule_dict=rule_dict)


def edit_record():
    name = dict(app=T('Application'),
                pair=T('Conversation'),
                filter=T('Filter'),
                rule=T('Rule'),
                ruleset=T('Rule Set'))

    table_name = request.args[0]
    table = db.get('monitor_%s' % table_name)
    record = table(request.args[1])
    form = SQLFORM(table, record, showid=False)
    if form.process(keepvalues=True).accepted:
        response.flash = 'form accepted'
    elif form.errors:
        response.flash = 'form has errors'
    return dict(form=form, tablename=name[table_name])


def new_record():
    name = dict(app=T('Application'),
                pair=T('Conversation'),
                filter=T('Filter'),
                rule=T('Rule'),
                ruleset=T('Rule Set'))
    table_name = request.args[0]
    table = db.get('monitor_%s' % table_name)
    form = SQLFORM(table)
    if form.process(keepvalues=True).accepted:
        response.flash = 'form accepted'
    elif form.errors:
        response.flash = 'form has errors'
    return dict(form=form, tablename=name[table_name])


#############################################
def select_app():
    apps = db(db.monitor_app).select()
    return dict(apps=apps)


def select_pair():
    try:
        apps = request.vars.app.split(',')
        pairs = db(db.monitor_pair.apps.contains(apps)).select()
    except:
        pairs = db(db.monitor_pair).select()
    span_ports = db(db.monitor_port).select()
    return dict(pairs=pairs,
                protocols=ip_protocol,
                ports=ports,
                span_ports=span_ports)


def create_policy():
    l = request.vars['pair'].split(',')
    pairs = db(db.monitor_pair.id.belongs(l)).select()
    devices = db(db.monitor_device).select()
    pairs_ports = [db.monitor_pair.span_ports.represent(item.span_ports) for item in pairs]
    return dict(pairs=pairs,
                devices=devices,
                pairs_ports=pairs_ports)


def submit_policy():
    import json

    data = json.loads(request.vars.data)

    directions = {}
    for d in data['direction']:
        k, v = d.split('/')
        directions[k] = v

    devices = {}
    for d in data['device']:
        k, v = d.split('/')
        if devices.has_key(k):
            devices[k].append(v)
        else:
            devices[k] = [v]

    ports = {}
    for p in data['port']:
        k, v = p.split('/')
        if ports.has_key(k):
            ports[k].append(v)
        else:
            ports[k] = [v]

    l = [p for p in directions]
    filters = db(db.monitor_filter.monitor_pair_id.belongs(l)).select(
        db.monitor_filter.id, db.monitor_filter.name,
        db.monitor_filter.monitor_pair_id)

    port_id = {}
    for p in db(db.monitor_port).select():
        port_id[p.name] = 'OF|%s@OF|%s' % (p.port_id, p.monitor_switch_id.switch_id)

    rules = []
    for f in filters:
        pairid = str(f.monitor_pair_id)

        if directions[pairid] == 'false':
            if f.name.startswith('FLT_B_'): continue
        if pairid not in devices: continue
        filter = f.name
        device = [d for d in devices[pairid]]
        if pairid not in ports:
            name = 'R_%s_D_%s' % (f.name, '_'.join(device))
            rules.append(dict(name=name, filter=filter, device=device))
        else:
            for p in ports[pairid]:
                sourcePort = port_id[p]
                name = 'R_%s_S_%s_D_%s' % (f.name, p, '_'.join(device))
                rules.append(dict(name=name, filter=filter, device=device, sourcePort=sourcePort))

    session.policy = rules
    return dict()


def review_policy():
    if session.policy:
        policy = session.policy
        filters = []
        filtername = []
        rules = []
        for r in policy:
            filtername.append(r['filter'])
            if 'sourcePort' in r:
                rule = xnc_rest.newRule(r['name'], r['filter'], r['device'], r['sourcePort'])
            else:
                rule = xnc_rest.newRule(r['name'], r['filter'], r['device'])
            rules.append(rule)

        rows = db(db.monitor_filter.name.belongs(filtername)).select()
        for r in rows:
            filter = xnc_rest.newFilter(r.name,
                                        networkSrc=r.networkSrc, networkDst=r.networkDst, protocol=r.protocol,
                                        transportPortSrc=r.transportPortSrc, transportPortDst=r.transportPortDst,
            )
            filters.append(filter)
        session.rules = rules
        session.filters = filters
        del session.policy
        return dict(rules=rules)
    redirect(URL('select_app'))


def install_policy():
    if session.filters and session.rules:
        rules = session.rules
        filters = session.filters
        __get_xnc().clearMonitorFiltersAndRules()
        __get_xnc().addMonitorFiltersAndRules(filters, rules)
        session.need_refresh_xnc = 'True'
        del session.filters


def save_policy():
    if session.rules:
        rulesetname = request.vars.name
        rules = session.rules
        for r in rules:
            r['monitor_filter'] = r['filter']
            del r['filter']
            r['device'] = ','.join(r['device'])
            r['description'] = r['name']
        try:
            l = db.monitor_rule.bulk_insert(rules)
        except:
            pass
        db.monitor_ruleset.insert(name=rulesetname, description='', rules=l)


#############################################
def select_ruleset():
    rulesets = db(db.monitor_ruleset).select()
    rules = db(db.monitor_rule).select()
    rule_dict = {}
    for r in rules:
        rule_dict[r.id] = r.name
    return dict(rulesets=rulesets, rule_dict=rule_dict)


def select_rule():
    rulesets = request.vars.ruleset
    if rulesets:
        rulesets = rulesets.split(',')
        rulelist = []
        for i in db(db.monitor_ruleset.id.belongs(rulesets)).select(db.monitor_ruleset.rules).as_list():
            rulelist.extend(i['rules'])
        rules = db(db.monitor_rule.id.belongs(rulelist)).select()
    else:
        rules = db(db.monitor_rule).select()

    return dict(rules=rules)


def install_rules():
    import json

    data = json.loads(request.vars.data)

    rulelist = data['rules']
    if rulelist:
        rules = db(db.monitor_rule.id.belongs(rulelist)).select().as_list()
        filterlist = []
        for r in rules:
            filterlist.append(r['monitor_filter'])
        filters = db(db.monitor_filter.name.belongs(filterlist)).select().as_list()
        for r in rules:
            r['filter'] = r['monitor_filter']
            r['device'] = r['device'].split(',')
            del r['monitor_filter']
        __get_xnc().clearMonitorFiltersAndRules()
        __get_xnc().addMonitorFiltersAndRules(filters, rules)
        session.need_refresh_xnc = 'True'


#############################################
def input5tuple():
    return dict()


def create_policy_5tuple():
    request.vars.para or redirect(URL('input5tuple'))
    tuple5 = []
    l = request.vars.para.split('_')
    tuple5 = [(l[i * 5], l[i * 5 + 1], l[i * 5 + 2], l[i * 5 + 3], l[i * 5 + 4]) for i in range(len(l) / 5)]
    tuple5 = list(set(tuple5))
    pairs = []
    for i, t in enumerate(tuple5):
        s = '%s:%s -> %s:%s, %s' % (t[0] or '*', t[1] or '*', t[3] or '*', t[4] or '*', t[2] or '*')
        pairs.append((i + 1, s, t))
    devices = db(db.monitor_device).select()
    ports = db(db.monitor_port.port_type != 'Delivery').select()
    session.pairs = pairs
    return dict(pairs=pairs,
                devices=devices,
                ports=ports)


def review_policy_5tuple():
    if request.vars.data:
        import json

        data = json.loads(request.vars.data)

        directions = {}
        for d in data['direction']:
            k, v = d.split('/')
            directions[k] = v

        devices = {}
        for d in data['device']:
            k, v = d.split('/')
            if devices.has_key(k):
                devices[k].append(v)
            else:
                devices[k] = [v]

        ports = {}
        for p in data['port']:
            k, v = p.split('/')
            if ports.has_key(k):
                ports[k].append(v)
            else:
                ports[k] = [v]

        port_id = {}
        for p in db(db.monitor_port).select():
            port_id[p.name] = 'OF|%s@OF|%s' % (p.port_id, p.monitor_switch_id.switch_id)

        rules = []
        filters = []
        for p in session.pairs:
            pairid = str(p[0])
            if pairid not in devices: continue
            pair_filters = []
            device = [d for d in devices[pairid]]
            filtername = 'FLT_A_TEMP_%s' % pairid
            pair_filters.append(filtername)
            filters.append(xnc_rest.newFilterByTuple5(filtername, p[2]))
            if directions[pairid] == 'true':
                filtername = 'FLT_B_TEMP_%s' % pairid
                reverseTuple5 = (p[2][3], p[2][4], p[2][2], p[2][0], p[2][1])
                pair_filters.append(filtername)
                filters.append(xnc_rest.newFilterByTuple5(filtername, reverseTuple5))

            for f in pair_filters:
                if pairid not in ports:
                    rulename = 'R_%s_D_%s' % (f, '_'.join(device))
                    rules.append(dict(name=rulename,
                                      filter=f,
                                      device=device))
                else:
                    for p in ports[pairid]:
                        sourcePort = port_id[p]
                        rulename = 'R_%s_S_%s_D_%s' % (f, p, '_'.join(device))
                        rules.append(dict(name=rulename,
                                          filter=f,
                                          device=device,
                                          sourcePort=sourcePort))

        session.rules = rules
        session.filters = filters
        try:
            del session.pairs
        except:
            pass
        return dict()
    return dict(rules=session.rules, filters=session.filters)


###########################################
def _new_filter_from_pair():
    pairs = db(db.monitor_pair).select()
    filters = []
    for p in pairs:
        networkSrc = p.src_ip
        networkDst = p.dst_ip
        protocol = p.protocol
        transportPortSrc = p.src_port
        transportPortDst = p.dst_port
        name = 'FA_' + p.name
        filter = xnc_rest.newFilter(name,
                                    networkSrc=networkSrc,
                                    networkDst=networkDst,
                                    protocol=protocol,
                                    transportPortSrc=transportPortSrc,
                                    transportPortDst=transportPortDst)
        filter['monitor_pair_id'] = p.id
        filters.append(filter)
        name = 'FB_' + p.name
        filter = xnc_rest.newFilter(name,
                                    networkDst=networkSrc,
                                    networkSrc=networkDst,
                                    protocol=protocol,
                                    transportPortSrc=transportPortDst,
                                    transportPortDst=transportPortSrc)
        filter['monitor_pair_id'] = p.id
        filters.append(filter)
    #    db.monitor_filter.bulk_insert(filters)
    __get_xnc.addMonitorFiltersAndRules(filters=filters)
    redirect(URL('xnc_refresh'))
    return dict(filters=filters)


##############################################################################
def form_from_dict():
    config = dict(color='black', language='English', car='ford')
    form = SQLFORM.dictform(config)
    my_extra_element = TR(LABEL('I agree to the terms and conditions'),
                          INPUT(_name='agree', value=True, _type='checkbox'))
    form[0].insert(-1, my_extra_element)
    if form.process(keepvalues=True).accepted:
        response.flash = 'form accepted'
    elif form.errors:
        response.flash = 'form has errors'
    return dict(form=form)
