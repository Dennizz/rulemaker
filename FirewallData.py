from jnpr.junos import Device

def connect(hostname,username):
	dev = Device(hostname,username)
	dev.open()
	return dev

def fetchZones(dev):
	result = {}
	for line in dev.cli("show configuration security zones").splitlines():
		if line.startswith('security-zone'):
			result[line.split()[1]]={}
	return result

def fetchAddresses(dev,zone):
	result = {}
	for line in dev.cli("show configuration security zones security-zone " + str(zone) + ' address-book').splitlines():
		if line.startswith('address '):
			result[line.split()[1]]=line.split()[2].strip(';')
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
	return result
				
def fetchApplications(dev):
	result = {}
	for line in dev.cli("show configuration applications").splitlines():
		if line.startswith('application-set'):
			break
		if line.startswith('application'):
			applicationName = line.split()[1]
			result[applicationName] = {}
		if 'destination-port' in line:
			result[applicationName]['destPort'] = line.split()[1].strip(';')
		if 'protocol' in line:
			result[applicationName]['protocol'] = line.split()[1].strip(';')
	return result

def fetchApplicationSets(dev):
	result = {}
	for line in dev.cli("show configuration applications").splitlines():
		if line.startswith('application '):
			continue
		if line.startswith('application-set'):
			applicationSetName = line.split()[1]
			result[applicationSetName] = []
		if 'application ' in line:
			result[applicationSetName].append(line.split()[1].strip(';'))
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
	
	for srczone in firewall['zones']:
		for dstzone in firewall['zones']:
			if srczone is not dstzone:
				bla = fetchPolicies(dev,srczone,dstzone) #need to insert this data in to the firewall dictionary
	
	dev.close()
	return firewall

#Put zones that you want to exclude here
zoneExcludeList = [
]
