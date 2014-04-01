from jnpr.junos import Device
import json
import time
debug = 0

def connect(hostname,username):
	dev = Device(hostname,user=username)
	dev.open()
	if debug == 1:
		print "Connected" + str(time.time())
	return dev

def fetchZones(dev):
	result = {}
	for line in dev.cli("show configuration security zones").splitlines():
		if line.startswith('security-zone'):
			result[line.split()[1]]={}
	if debug == 1:
		print "Zones fetched" + str(time.time())
	return result

def fetchAddresses(dev,zone):
	result = {}
	for line in dev.cli("show configuration security zones security-zone " + str(zone) + ' address-book').splitlines():
		if line.startswith('address-set'):
			break
		if line.startswith('address '):
			if '{' in line:
				name = line.split()[1]
				continue
			else:
				result[line.split()[1]]=line.split()[2].strip(';')
				continue
		if 'description' in line:
			description = line.split('"')[1]
			continue
		if '/' in line:
			result[name] = line.split()[0].strip(';')
			
	if debug == 1:
		print "Addresses fetched for zone " + str(zone)  + str(time.time())
	return result

def fetchAddressSets(dev,zone):
	result = {}
	for line in dev.cli("show configuration security zones security-zone " + str(zone) + ' address-book').splitlines():
		if line.startswith('address '):
			continue
		if line.startswith('address-set'):
			addressSetName = line.split()[1]
			result[addressSetName] = []
		if 'address ' in line:
			result[addressSetName].append(line.split()[1].strip(';'))
	if debug == 1:
		print "Address Sets fetched for zone " + str(zone)  + str(time.time())
	return result
				
def fetchApplications(dev): #This function needs some serious cleanup
	result = {}

	def getApplications(applications):
		result = {}

		def writeDict(applicationName,protocol,destPort=''):
			result[applicationName].append({
				'protocol' : protocol,
				'destPort' : destPort,
			})

		for line in applications.splitlines():
			if line.startswith('application-set'):
				break
			if line.startswith('application'):
				applicationName = line.split()[1]
				result[applicationName] = []
				continue
			if 'term' in line:
				offset = 0
				if line.split()[2] == 'alg':
					offset = 2
				protocol = line.split()[3+offset].strip(';')
				if (protocol == 'tcp' or protocol == 'udp') and ('destination-port' in line):
					destPort = line.split()[5+offset].strip(';')
					writeDict(applicationName,protocol,destPort)
					protocol = ''
					destPort = ''
				else:
					writeDict(applicationName,protocol)
					protocol = ''
					destPort = ''
				continue
			if line.startswith('    destination-port'):
				destPort = line.split()[1].strip(';') 
			if line.startswith('    protocol'):
				protocol = line.split()[1].strip(';')
			if line.startswith('}') and protocol != '':
				writeDict(applicationName,protocol,destPort)
		#print json.dumps(result, indent=4)
		return result

	customApps = getApplications(dev.cli("show configuration applications"))
	defaultApps = getApplications(dev.cli("show configuration groups junos-defaults applications"))
	result = dict(list(customApps.items()) + list(defaultApps.items()))

	if debug == 1:
		print "Applications fetched" + str(time.time())

	return result

def fetchApplicationSets(dev):
	result = {}
	def getApplicationSets(applications):
		result = {}
		for line in applications.splitlines():
			if line.startswith('#'):
				continue
			if line.startswith('application '):
				continue
			if line.startswith('application-set'):
				applicationSetName = line.split()[1]
				result[applicationSetName] = []
			if 'application ' in line:
				result[applicationSetName].append(line.split()[1].strip(';'))
		return result	

	customAppSets = getApplicationSets(dev.cli("show configuration applications"))
	defaultAppSets = getApplicationSets(dev.cli("show configuration groups junos-defaults applications"))
	result = dict(list(customAppSets.items()) + list(defaultAppSets.items()))

	if debug == 1:
		print "Application Sets fetched" + str(time.time())

	return result

def fetchPolicies(dev,src,dst):

	def getItemList(line):
			#handle multiple items
			if '[' and ']' in line:
				items = line.split()[2:-1]
			#handle single item
			else:
				items = [ line.split()[1].strip(';') ]
			return items

	result = {}
	for line in dev.cli("show configuration security policies from-zone " + str(src) + " to-zone " + str(dst)).splitlines():
		if line.startswith('apply-groups'): #no parsing for apply-groups implemeted yet
			continue
		if line.startswith('inactive'):
			state = 'inactive'
			name = line.split()[2]
			result[name] = {}
			result[name]['state'] = state
			continue
		elif line.startswith('policy'):
			state = 'active'
			name = line.split()[1]
			result[name] = {}
			result[name]['state'] = state
			continue
		if 'source-address' in line:
			result[name]['sources'] = getItemList(line)
			continue
		if 'destination-address' in line:
			result[name]['destinations'] = getItemList(line)
			continue
		if 'application' in line:
			result[name]['applications'] = getItemList(line)
			continue
		if 'deny' in line or 'permit' in line or 'reject' in line:
			result[name]['action'] = line.split()[0].strip(';')
	return result

def getPolicyRelations(dev):
	result = []
	for line in dev.cli("show configuration security policies").splitlines():
		if line.startswith('from'):
			policyPair = {}
			policyPair['from-zone'] = line.split()[1]
			policyPair['to-zone'] = line.split()[3]
			result.append(policyPair)
	return result

def CreateFirewallModel(hostname,username):
	firewall = {}
	dev = connect(hostname,username)

	firewall['zones'] = fetchZones(dev)
	firewall['applications'] = fetchApplications(dev)
	firewall['applicationSets'] = fetchApplicationSets(dev)
	
	for zone in firewall['zones']:
		firewall['zones'][zone]['addresses'] = {}
		addresses = fetchAddresses(dev,zone)
		for name, address in addresses.iteritems():
			firewall['zones'][zone]['addresses'][name]=address
	
		firewall['zones'][zone]['addressSets'] = {}
		addressSets = fetchAddressSets(dev,zone)
		for name, addressList in addressSets.iteritems():
			firewall['zones'][zone]['addressSets'][name]=addressList
	
	firewall['policies'] = {}
	for policyPairs in getPolicyRelations(dev):
		if not policyPairs['from-zone'] in firewall['policies']:
			firewall['policies'][policyPairs['from-zone']] = []
		firewall['policies'][policyPairs['from-zone']].append({policyPairs['to-zone'] : fetchPolicies(dev,policyPairs['from-zone'],policyPairs['to-zone'])})
	#print json.dumps(firewall, indent=4)
	dev.close()
	return firewall

#Put zones that you want to exclude here
zoneExcludeList = [
]
