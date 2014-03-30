from django.shortcuts import render, render_to_response
from models import *
from FirewallData import CreateFirewallModel, zoneExcludeList
# Create your views here.

def updateFirewall(request,firewall):
	#This function fetches all relevant data from a Juniper firewall, clears all current data for this firewall in the database and then stores the current data.
	firewall = Firewall.objects.get(hostname = firewall)
	data = CreateFirewallModel(firewall.hostname,firewall.username)

	#Clear existing data
	Application.objects.filter(firewall = firewall).delete()
	ApplicationSet.objects.filter(firewall = firewall).delete()
	Address.objects.filter(firewall = firewall).delete()
	AddressSet.objects.filter(firewall = firewall).delete()
	Zone.objects.filter(firewall = firewall).delete()
	Policy.objects.filter(firewall = firewall).delete()

	#Create applications in database
	for appName,values in data['applications'].iteritems():
		#Not all applications have destination ports, so we need to check if the key exists and otherwise create a key with an empty value
		if not 'destPort' in values:
			values['destPort'] = ''
		ApplicationModel = Application(firewall = firewall,	name = appName,	protocol = values['protocol'], destPort = values['destPort'] )
		ApplicationModel.save()

	#Create application sets in database
	for appSetName, values in data['applicationSets'].iteritems():
		ApplicationSetModel = ApplicationSet(firewall = firewall, name = appSetName )
		ApplicationSetModel.save()

		for app in values:
			appObject = Application.objects.get(name = app, firewall = firewall)
			appSet = ApplicationSet.objects.get(name = appSetName, firewall = firewall)
			appSet.applications.add(appObject)
			appSet.save()

	#Create zones and address objects
	for zone, addresses in data['zones'].iteritems():
		if zone not in zoneExcludeList:
			#Create zone in database
			zoneModel = Zone(firewall = firewall, name = zone) 
			zoneModel.save()
			zoneObject = Zone.objects.get(firewall = firewall, name = zone)
			for name, cidr in addresses['addresses'].iteritems():
				address = cidr.split('/')[0]
				netmaskLength = int(cidr.split('/')[1])
				Addressmodel = Address(firewall = firewall, zone = zoneObject, name = name, address = address, netmaskLength = netmaskLength)
				Addressmodel.save()

			for name, values in addresses['addressSets'].iteritems():
				addressSetModel = AddressSet(firewall = firewall, zone = zoneObject, name = name)
				addressSetModel.save()

				for address in values:
					addressSet = AddressSet.objects.get(firewall = firewall, zone = zoneObject, name = name)
					addressObject = Address.objects.get(firewall = firewall, zone = zoneObject, name = address)
					addressSet.addresses.add(addressObject)
					addressSet.save()

	return render_to_response( "rulemaker/index.html", {'data' : data} )