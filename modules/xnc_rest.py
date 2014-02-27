__author__ = "zhutong <zhtong@cisco.com>"
__version__ = '0.1'

from restful_lib import Connection
import json
import logging
import logging.config

log = logging.getLogger('XMC-REST-API')
log.setLevel(logging.INFO)
formatter = logging.Formatter('[%(name)-12s %(levelname)-8s] %(message)s')
logHandler = logging.StreamHandler()
logHandler.setFormatter(formatter)
log.addHandler(logHandler)


class XNCRest:
    '''
    This class wraps XNC northbound Restful API. 
    For more information, refer to the "Cisco XNC REST API Documentation":
    https://developer.cisco.com/site/tech/networking/sdn/xnc/apis-and-docs/xnc-rest-api/
    '''

    NBAPIV2 = '/controller/nb/v2/'
    SWITCHMANAGER = 'switchmanager'
    FLOWPROGRAMMER = 'flowprogrammer'
    TOPOLOGY = 'topology'
    HOSTTRACKER = 'hosttracker'
    MONITOR = 'monitor'
    STATISTICS = 'statistics'

    def __init__(self, base_url, username, password, container='default'):
        '''
        @base_url: the URL for the XNC, Eg. "http://localhost:8080".
        @username: username for XNC.
        @password: password for XNC.
        @container: name of the Container, default is "default".
        '''
        self._connection = Connection(base_url,
                                      username=username,
                                      password=password)
        self.container = container

    def _get(self, resource, operation_name):
        '''
        Low level encapsulation for XNC Restful API "GET" method.
        @resource: resource.
        '''
        resource = self.NBAPIV2 + resource
        result = self._connection.request_get(resource)
        headers = result['headers']
        body = result['body']
        if headers['status'] != '200':
            log.warning('%s failed: %s.\n\t\t\tGET: %s', operation_name, body, resource)
            return body
        else:
            log.debug('%s successed.\n\t\t\tGET: %s', operation_name, resource)
        return json.loads(body)

    def _put(self, resource, data, operation_name):
        '''
        Low level encapsulation for XNC Restful API "PUT" method.
        @resource: resource.
        '''
        resource = self.NBAPIV2 + resource
        result = self._connection.request_put(resource,
                                              body=json.dumps(data),
                                              headers={'content-type': 'application/json'})
        headers = result['headers']
        body = result['body']
        if headers['status'] not in ['200', '201']:
            log.warning('%s failed: %s.\n\t\t\tPUT: %s', operation_name, body, resource)
        else:
            log.debug('%s successed.\n\t\t\tPUT: %s', operation_name, resource)
        return body

    def _delete(self, resource, operation_name):
        '''
        Low level encapsulation for XNC Restful API "DELETE" method.
        @resource: resource.
        '''
        resource = self.NBAPIV2 + resource
        result = self._connection.request_delete(resource,
                                                 headers={'content-type': 'application/json'})
        headers = result['headers']
        body = result['body']
        if headers['status'] != '204':
            log.warning('%s failed: %s.\n\t\t\tDELETE: %s', operation_name, body, resource)
        else:
            log.debug('%s successed.\n\t\t\tDELETE: %s', operation_name, resource)
        return body

    def _post(self, resource, operation_name):
        '''
        Low level encapsulation for XNC Restful API "POST" method.
        @resource: resource.
        '''
        resource = self.NBAPIV2 + resource
        result = self._connection.request_post(resource,
                                               headers={'content-type': 'application/json'})
        headers = result['headers']
        body = result['body']
        if headers['status'] != '200':
            log.warning('%s failed: %s.\n\t\t\tPOST: %s', operation_name, body, resource)
        else:
            log.debug('%s successed.\n\t\t\tPOST: %s', operation_name, resource)
        return body

    def getTopo(self):
        '''
        Retrieve the Topology.
        Return a List of EdgeProps each EdgeProp represent an Edge of the graph with the corresponding properties attached to it.

        Example request URL:
        http://localhost:8080/controller/nb/v2/topology/default
        '''
        resource = '/'.join((self.TOPOLOGY,
                             self.container))
        return self._get(resource, 'GetTopo')

    def getAllNodes(self):
        '''
        Retrieve a list of all the nodes and their properties in the network.
        Example request URL:
        http://localhost:8080/controller/nb/v2/switchmanager/default/nodes
        '''
        resource = '/'.join((self.SWITCHMANAGER,
                             self.container,
                             'nodes'))
        return self._get(resource, 'GetAllNodes')

    def saveNodesConfig(self):
        '''
        Save the current switch configurations.
        Example request URL:
        http://localhost:8080/controller/nb/v2/switchmanager/default/save
        '''
        resource = '/'.join((self.SWITCHMANAGER,
                             self.container,
                             'save'))
        return self._post(resource, 'SaveNodesConfig')

    def getNodeConnectors(self, nodeid, nodetype='OF'):
        '''
        Retrieve a list of all the nodeconnectors and their properties in a given node.
        Example request URL:
        http://localhost:8080/controller/nb/v2/switchmanager/default/node/OF/00:00:00:00:00:00:00:01
        '''
        resource = '/'.join((self.SWITCHMANAGER,
                             self.container,
                             'node',
                             nodetype,
                             nodeid))
        return self._get(resource, 'GetNodeConnectors')

    def getAllFlows(self):
        '''
        Returns a list of Flows configured on the given container.
        Example request URL:
        http://localhost:8080/controller/nb/v2/flowprogrammer/default
        '''
        resource = '/'.join((self.FLOWPROGRAMMER,
                             self.container))
        return self._get(resource, 'GetAllFlows')

    def getNodeFlows(self, nodeid, nodetype='OF'):
        '''
        Returns a list of Flows configured on a Node in a given container.
        Example request URL:
        http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/00:00:00:00:00:00:00:01
        '''
        resource = '/'.join((self.FLOWPROGRAMMER,
                             self.container,
                             'node',
                             nodetype,
                             nodeid))
        return self._get(resource, 'GetNodeFlows')

    def getNodeFlowByName(self, nodeid, flowname, nodetype='OF'):
        '''
        Returns the flow configuration matching a human-readable name and nodeId on a given Container.
        Example request URL:
        http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/00:00:00:00:00:00:00:01/staticFlow/flow1
        '''
        resource = '/'.join((self.FLOWPROGRAMMER,
                             self.container,
                             'node',
                             nodetype,
                             nodeid,
                             'staticFlow',
                             flowname))
        return self._get(resource, 'getNodeFlowByName')

    def insertFlow(self, nodeid, flow, nodetype='OF'):
        '''
        Add a flow configuration. If a flow by the given name already exists, this method will respond with a non-successful status response.
        Example request URL:
        http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/00:00:00:00:00:00:00:01/staticFlow/flow1
        '''
        resource = '/'.join((self.FLOWPROGRAMMER,
                             self.container,
                             'node',
                             nodetype,
                             nodeid,
                             'staticFlow',
                             flow['name']))
        return self._put(resource, flow, 'InsertFlow')

    def deleteNodeFlowByName(self, nodeid, flowname, nodetype='OF'):
        '''
        Delete a Flow configuration.
        Example request URL:
        http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/00:00:00:00:00:00:00:01/staticFlow/flow1
        '''
        resource = '/'.join((self.FLOWPROGRAMMER,
                             self.container,
                             'node',
                             nodetype,
                             nodeid,
                             'staticFlow',
                             flowname))
        return self._delete(resource, 'DeleteNodeFlowByName')

    def toggleFlow(self, nodeid, flowname, nodetype='OF'):
        '''
        Toggle "install/uninstall" a Flow configuration. 
        Example request URL:
        http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/00:00:00:00:00:00:00:01/staticFlow/flow1
        '''
        resource = '/'.join((self.FLOWPROGRAMMER,
                             self.container,
                             'node',
                             nodetype,
                             nodeid,
                             'staticFlow',
                             flowname))
        return self._post(resource, 'ToggleFlow')

    def getHost(self, ip):
        '''
        Returns a host that matches the IP Address value passed as parameter.
        Example request URL:
        http://localhost:8080/controller/nb/v2/hosttracker/default/address/1.1.1.1
        '''
        resource = '/'.join((self.HOSTTRACKER,
                             self.container,
                             'address',
                             ip))
        return self._get(resource, 'GetHost')

    def addHost(self, ip, host):
        '''
        Add a Static Host configuration. If a host by the given address already exists, this method will respond with a non-successful status response.
        Example request URL:
        http://localhost:8080/controller/nb/v2/hosttracker/default/address/1.1.1.1
        '''
        resource = '/'.join((self.HOSTTRACKER,
                             self.container,
                             'address',
                             ip))
        return self._put(resource, host, 'AddHost')

    def deleteHost(self, ip, host):
        '''
        Delete a Static Host configuration
        Example request URL:
        http://localhost:8080/controller/nb/v2/hosttracker/default/address/1.1.1.1
        '''
        resource = '/'.join((self.HOSTTRACKER,
                             self.container,
                             'address',
                             ip))
        return self._delete(resource, 'DeleteHost')

    def getActiveHosts(self):
        '''
        Returns a list of all Hosts : both configured via PUT API and dynamically learnt on the network.
        Example request URL:
        http://localhost:8080/controller/nb/v2/hosttracker/default/hosts/active
        '''
        resource = '/'.join((self.HOSTTRACKER,
                             self.container,
                             'hosts/active'))
        return self._get(resource, 'GetActiveHosts')

    def getInactiveHosts(self):
        '''
        Returns a list of Hosts that are statically configured and are connected to a NodeConnector that is down.
        Example request URL:
        http://localhost:8080/controller/nb/v2/hosttracker/default/hosts/inactive
        '''
        resource = '/'.join((self.HOSTTRACKER,
                             self.container,
                             'hosts/inactive'))
        return self._get(resource, 'GetInactiveHosts')

    def getRootMonitorNode(self):
        '''
        Get currently active root node
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/rootnode
        '''
        resource = '/'.join((self.MONITOR, 'rootnode'))
        return self._get(resource, 'GetRootMonitorNode')

    def getAllMonitorPorts(self):
        '''
        Get all monitor ports
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/ports
        '''
        resource = '/'.join((self.MONITOR, 'ports'))
        return self._get(resource, 'GetAllMonitorPorts')

    def addMonitorPort(self, port):
        '''
        Add/Update a monitor port type
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/port
        '''
        resource = '/'.join((self.MONITOR, 'port'))
        return self._put(resource, port, 'addMonitorPort')

    def deleteMonitorPort(self, nodeid, portid):
        '''
        Remove a monitor port configuration
        Request URL:
        http://localhost:8080/controller/nb/v2/monitor/port/OF/00:00:00:00:00:00:00:04/OF/4
        '''
        resource = '/'.join((self.MONITOR, 'nodeconnector/OF', nodeid, 'OF', portid))
        return self._delete(resource, 'DeleteMonitorPort')

    def getAllMonitorDevices(self):
        '''
        Get all monitor devices
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/devices
        '''
        resource = '/'.join((self.MONITOR, 'devices'))
        return self._get(resource, 'GetAllMonitorDevices')

    def getMonitorDeviceByName(self, devicename):
        '''
        Get monitoring device by name
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/device/Device3
        '''
        resource = '/'.join((self.MONITOR, 'device', devicename))
        return self._get(resource, 'GetMonitorDeviceByName')

    def addMonitorDevice(self, devicename, device):
        '''
        Add a monitoring device
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/device/Device3
        '''
        resource = '/'.join((self.MONITOR, 'device', devicename))
        return self._put(resource, device, 'addMonitorDevice')

    def deleteMonitorDeviceByName(self, devicename):
        '''
        Delete a monitor device
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/device/Device3
        '''
        resource = '/'.join((self.MONITOR, 'device', devicename))
        return self._delete(resource, 'DeleteMonitorDevice')

    def getAllMonitorFilters(self):
        '''
        Get all monitor filters
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/filters
        '''
        resource = '/'.join((self.MONITOR, 'filters'))
        return self._get(resource, 'GetAllMonitorFilters')

    def getMonitorFilterByName(self, filtername):
        '''
        Get monitoring filter by name
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/filter/Filter1
        '''
        resource = '/'.join((self.MONITOR, 'filter', filtername))
        return self._get(resource, 'GetMonitorFilterByName')

    def addMonitorFilter(self, filter):
        '''
        Add a monitoring filter
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/filter/Filter1
        '''
        filtername = filter['name']
        resource = '/'.join((self.MONITOR, 'filter', filtername))
        return self._put(resource, filter, 'AAddMonitorFilter')

    def deleteMonitorFilterByName(self, filtername):
        '''
        Delete a monitor filter by name
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/filter/Filter1
        '''
        resource = '/'.join((self.MONITOR, 'filter', filtername))
        return self._delete(resource, 'DeleteMonitorFilterByName')

    def getAllMonitorRules(self):
        '''
        Get all monitor rules
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/rules
        '''
        resource = '/'.join((self.MONITOR, 'rules'))
        return self._get(resource, 'GetAllMonitorRules')

    def getMonitorRuleByName(self, rulename):
        '''
        Get monitoring rule by name
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/rule/MyRule1
        '''
        resource = '/'.join((self.MONITOR, 'rule', rulename))
        return self._get(resource, 'GetMonitorRuleByName')

    def addMonitorRule(self, rule):
        '''
        Add/Modify a monitoring rule
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/rule/MyRule1
        
        Request body in JSON like this:
        {
            "name": "rule-name",
            "filter": "filter-name",
            "device": ["device1", "device2"],
            "sourcePort": "OF|3@OF|00:00:00:00:00:00:00:02"
        }
        '''
        rulename = rule['name']
        resource = '/'.join((self.MONITOR, 'rule', rulename))
        return self._put(resource, rule, 'AddMonitorRule')

    def deleteMonitorRuleByName(self, rulename):
        '''
        Delete a monitor rule by name
        Example request URL:
        http://localhost:8080/controller/nb/v2/monitor/rule/MyRule1
        '''
        resource = '/'.join((self.MONITOR, 'rule', rulename))
        return self._delete(resource, 'DeleteMonitorRuleByName')

    def getAllFlowStatistics(self):
        '''
        Returns a list of all Flow Statistics from all the Nodes.
        Example request URL:
        http://localhost:8080/controller/nb/v2/statistics/default/flow
        '''
        resource = '/'.join((self.STATISTICS, self.container, 'flow'))
        return self._get(resource, 'GetAllFlowStatistics')

    def getAllPortStatistics(self):
        '''
        Returns a list of all Port Statistics from all the Nodes.
        Example request URL:
        http://localhost:8080/controller/nb/v2/statistics/default/port
        '''
        resource = '/'.join((self.STATISTICS, self.container, 'port'))
        return self._get(resource, 'GetAllPortStatistics')

    def getAllTableStatistics(self):
        '''
        Returns a list of all Table Statistics from all the Nodes.
        Example request URL:
        http://localhost:8080/controller/nb/v2/statistics/default/table
        '''
        resource = '/'.join((self.STATISTICS, self.container, 'table'))
        return self._get(resource, 'GetAllTableStatistics')

    def getNodeFlowStatistics(self, nodeid, nodetype='OF'):
        '''
        Returns a list of Flow Statistics for a given Node.
        Example request URL:
        http://localhost:8080/controller/nb/v2/statistics/default/flow/node/OF/00:00:00:00:00:00:00:01
        '''
        resource = '/'.join((self.STATISTICS,
                             self.container,
                             'flow/node',
                             nodetype,
                             nodeid))
        return self._get(resource, 'GetNodeFlowStatistics')

    def getNodePortStatistics(self, nodeid, nodetype='OF'):
        '''
        Returns a list of all the Port Statistics across all the NodeConnectors in a given Node.
        Example request URL:
        http://localhost:8080/controller/nb/v2/statistics/default/port/node/OF/00:00:00:00:00:00:00:01
        '''
        resource = '/'.join((self.STATISTICS,
                             self.container,
                             'port/node',
                             nodetype,
                             nodeid))
        return self._get(resource, 'GetNodePortStatistics')

    def getNodeTableStatistics(self, nodeid, nodetype='OF'):
        '''
        Returns a list of all the Table Statistics on a specific node.
        Example request URL:
        http://localhost:8080/controller/nb/v2/statistics/default/table/node/OF/00:00:00:00:00:00:00:01
        '''
        resource = '/'.join((self.STATISTICS,
                             self.container,
                             'table/node',
                             nodetype,
                             nodeid))
        return self._get(resource, 'GetNodeTableStatistics')


    def addMonitorFiltersAndRules(self,
                                  filters=[],
                                  rules=[]):
        for filter in filters:
            self.addMonitorFilter(filter)
        for rule in rules:
            self.addMonitorRule(rule)
        rules = self.getAllMonitorRules()
        filters = self.getAllMonitorFilters()
        return filters, rules


    def clearMonitorFiltersAndRules(self):
        rules = self.getAllMonitorRules()
        if 'No rules' not in rules:
            for r in rules['rule']:
                self.deleteMonitorRuleByName(r['name'])
        filters = self.getAllMonitorFilters()
        if 'No filters found.' not in filters:
            for f in filters['filter']:
                self.deleteMonitorFilterByName(f['name'])

    def refreshMonitor(self, temp_file_folder):
        output = {}
        output['AllNodes'] = self.getAllNodes()
        output['AllPorts'] = self.getAllMonitorPorts()
        output['AllDevices'] = self.getAllMonitorDevices()
        output['AllFilters'] = self.getAllMonitorFilters()
        if output['AllFilters'] == 'No filters found.':
            output['AllFilters'] = {'filter': []}
        output['AllRules'] = self.getAllMonitorRules()
        if 'No rules' in output['AllRules']:
            output['AllRules'] = {'rule': []}
        import os
        f = os.path.join(temp_file_folder,'monitordataset.json')
        open(f, 'w').write(json.dumps(output))
        return output


    def loginTest(self):
        return self.getAllNodes()


def newFlow(name, nodeid, switchtype='OF',
            ingressPort='', actions=[],
            dlSrc='', dlDst='', etherType='',
            vlanId='', vlanPriority='',
            nwSrc='', nwDst='', tosBits='',
            protocol='', tpSrc='', tpDst='',
            hardTimeout='', idleTimeout='',
            installInHw=True, priority=500, cookie='',
):
    node = {'type': switchtype, 'id': nodeid}
    flow = dict(name=name,
                node=node,
                ingressPort=ingressPort,
                actions=actions,
                dlSrc=dlSrc,
                dlDst=dlDst,
                etherType=etherType,
                vlanId=vlanId,
                vlanPriority=vlanPriority,
                nwSrc=nwSrc,
                nwDst=nwDst,
                tosBits=tosBits,
                protocol=protocol,
                tpSrc=tpSrc,
                tpDst=tpDst,
                hardTimeout=hardTimeout,
                idleTimeout=idleTimeout,
                installInHw=installInHw,
                priority=priority,
                cookie=cookie)
    return flow


def newFilter(name, datalayerSrc='', datalayerDst='',
              etherType='0x0800', vlanId='', vlanPriority='',
              networkSrc='', networkDst='', tosBits='',
              protocol='', transportPortSrc='', transportPortDst='',
              priority='500', vlanToSet=''
):
    return dict(name=name,
                datalayerSrc=datalayerSrc,
                datalayerDst=datalayerDst,
                etherType=etherType,
                vlanId=vlanId,
                vlanPriority=vlanPriority,
                networkSrc=networkSrc,
                networkDst=networkDst,
                tosBits=tosBits,
                protocol=protocol,
                transportPortSrc=transportPortSrc,
                transportPortDst=transportPortDst,
                priority=priority,
                vlanToSet=vlanToSet)


def newRule(name, filter, device, sourcePort=None):
    '''
    Create rule.
    @name: rule name, string
    @filter: filter name, string
    @device: a list of device's name, [string, string,...]
    @sourcePort: Id for edge port, string, Eg. OF|3@OF|00:00:00:00:00:00:00:02 
    '''
    return dict(name=name,
                filter=filter,
                device=device,
                sourcePort=sourcePort)


def refresh(base_url='http://127.0.0.1:8080',
            username='admin',
            password='admin'):
    xncrest = XNCRest(base_url, username, password)

    output = {}
    output['AllNodes'] = xncrest.getAllNodes()
    output['AllPorts'] = xncrest.getAllMonitorPorts()
    output['AllDevices'] = xncrest.getAllMonitorDevices()
    output['AllFilters'] = xncrest.getAllMonitorFilters()
    if output['AllFilters'] == 'No filters found.':
        output['AllFilters'] = {'filter': []}
    output['AllRules'] = xncrest.getAllMonitorRules()
    if 'No rules' in output['AllRules']:
        output['AllRules'] = {'rule': []}

    open('monitordataset.json', 'w').write(json.dumps(output))
    return output


def getDataset(temp_file_folder):
    import os, json

    file_name = os.path.join(temp_file_folder, 'monitordataset.json')
    with open(file_name) as f:
        output = json.loads(f.read())
    return output


def addMonitorFiltersAndRules(filters=[],
                              rules=[],
                              base_url='http://127.0.0.1:8080',
                              username='admin',
                              password='admin'):
    xncrest = XNCRest(base_url, username, password)

    for filter in filters:
        xncrest.addMonitorFilter(filter)
    for rule in rules:
        xncrest.addMonitorRule(rule)
    rules = xncrest.getAllMonitorRules()
    filters = xncrest.getAllMonitorFilters()
    return filters, rules


def clearMonitorFiltersAndRules(
        base_url='http://127.0.0.1:8080',
        username='admin',
        password='admin'):
    xncrest = XNCRest(base_url, username, password)
    rules = xncrest.getAllMonitorRules()
    if 'No rules' not in rules:
        for r in rules['rule']:
            xncrest.deleteMonitorRuleByName(r['name'])
    filters = xncrest.getAllMonitorFilters()
    if 'No filters found.' not in filters:
        for f in filters['filter']:
            xncrest.deleteMonitorFilterByName(f['name'])
