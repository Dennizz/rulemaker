from django.shortcuts import render, render_to_response
from django.template import Context, RequestContext
from models import *
from FirewallData import CreateFirewallModel
# Create your views here.

def viewAddress(request, firewall, zone, address):
	firewall = Firewall.objects.get(hostname = firewall)
	zone = Zone.objects.get(firewall = firewall, name = zone)
	address = Address.objects.get(firewall = firewall, zone = zone, name = address)
	return render_to_response( "rulemaker/viewAddress.html", {'address' : address} )

def viewAddressSet(request, firewall, zone, addressSet):
	firewall = Firewall.objects.get(hostname = firewall)
	zone = Zone.objects.get(firewall = firewall, name = zone)
	addressSet = Address.objects.get(firewall = firewall, zone = zone, name = addressSet)
	return render_to_response( "rulemaker/viewAddress.html", {'addressSet' : addressSet} )

def viewApplication(request, firewall, application):
	firewall = Firewall.objects.get(hostname = firewall)
	application = Application.objects.get(firewall = firewall, name = application)
	return render_to_response( "rulemaker/viewApplication.html", {'application' : application} )

def viewApplicationSet(request, firewall, applicationSet):
	firewall = Firewall.objects.get(hostname = firewall)
	application = ApplicationSet.objects.get(firewall = firewall, name = applicationSet)
	return render_to_response( "rulemaker/viewApplicationSet.html", {'applicationSet' : applicationSet} )

def ruleOverview(request, firewall):

	firewall = Firewall.objects.get(hostname = firewall)
	zones = Zone.objects.filter(firewall = firewall)

	if request.method == 'POST': #Input validation needs to be added
		srcZone = request.POST.get('fromZone')
		dstZone = request.POST.get('toZone')
		fromZone = Zone.objects.get(firewall = firewall, name = srcZone)
		toZone = Zone.objects.get(firewall = firewall, name = dstZone)
		policies = Policy.objects.filter(firewall = firewall, fromZone = fromZone, toZone = toZone)
		print policies
		return render_to_response( "rulemaker/rules.html", {'policies' : policies, 'zones' : zones, 'fromZone' : fromZone, 'toZone' : toZone, 'firewall' : firewall }, context_instance = RequestContext(request))
	else:
		return render_to_response( "rulemaker/ruleOverview.html", { 'zones' : zones }, context_instance = RequestContext(request))

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
		ApplicationModel = Application(firewall = firewall, name = appName)
		ApplicationModel.save()
		for appData in values:
			ApplicationPortModel = ApplicationPort(firewall = firewall, application = ApplicationModel, protocol = appData['protocol'], destPort = appData['destPort'])
			ApplicationPortModel.save()

	#Create application sets in database
	for appSetName, values in data['applicationSets'].iteritems():
		ApplicationSetModel = ApplicationSet(firewall = firewall, name = appSetName )
		ApplicationSetModel.save()
		for app in values:
			appObject = Application.objects.get(name = app, firewall = firewall)
			ApplicationSetModel.applications.add(appObject)
		ApplicationSetModel.save()

	#Create zones and address objects
	zoneExcludeList = list(ExcludeZone.objects.filter(firewall = firewall))
	for zone, addresses in data['zones'].iteritems():
		skip = 0
		for ExcludedZone in zoneExcludeList:
			if zone == ExcludedZone.name:
				skip = 1
		if skip == 0:
			#Create zone in database
			zoneModel = Zone(firewall = firewall, name = zone) 
			zoneModel.save()
			zoneObject = Zone.objects.get(firewall = firewall, name = zone)
			for name, cidr in addresses['addresses'].iteritems():
				address = cidr.split('/')[0]
				netmaskLength = int(cidr.split('/')[1])
				Addressmodel = Address(firewall = firewall, zone = zoneObject, name = name, address = address, netmaskLength = netmaskLength)
				Addressmodel.save()

			#Add default addresses any, any-ipv4 and any-ipv6 for all zones
			Addressmodel = Address(firewall = firewall, zone = zoneObject, name = 'any', address = '0.0.0.0', netmaskLength = '0')
			Addressmodel.save()
			Addressmodel = Address(firewall = firewall, zone = zoneObject, name = 'any-ipv6', address = '0::', netmaskLength = '0')
			Addressmodel.save()
			Addressmodel = Address(firewall = firewall, zone = zoneObject, name = 'any-ipv4', address = '0.0.0.0', netmaskLength = '0')
			Addressmodel.save()

			for name, values in addresses['addressSets'].iteritems():
				addressSetModel = AddressSet(firewall = firewall, zone = zoneObject, name = name)
				addressSetModel.save()

				for address in values:
					addressSet = AddressSet.objects.get(firewall = firewall, zone = zoneObject, name = name)
					addressObject = Address.objects.get(firewall = firewall, zone = zoneObject, name = address)
					addressSet.addresses.add(addressObject)
					addressSet.save()

	#Create policy objects
	for fromZone,fromZoneData in data['policies'].iteritems():
		skip = 0
		for ExcludedZone in zoneExcludeList:
			if fromZone == ExcludedZone.name:
				skip = 1
		if skip == 0:		
			fromZoneObject = Zone.objects.get(firewall = firewall, name = fromZone)
			for entry in fromZoneData:
				for toZone, toZoneData, in entry.iteritems():
					skip = 0
					for ExcludedZone in zoneExcludeList:
						if toZone == ExcludedZone.name:
							skip = 1
					if skip == 0:
						toZoneObject = Zone.objects.get(firewall = firewall, name = toZone)
						for policy, policyData in toZoneData.iteritems():
							policyModel = Policy(firewall = firewall, name = policy, fromZone = fromZoneObject, toZone = toZoneObject, state=policyData['state'], action=policyData['action'])
							policyModel.save()
							policyObject = Policy.objects.get(firewall = firewall, name = policy, fromZone = fromZoneObject, toZone = toZoneObject)
							for source in policyData['sources']:
								try:
									sourceObject = Address.objects.get(firewall = firewall, zone = fromZoneObject, name = source)
									policyObject.srcAddress.add(sourceObject)
								except:
									sourceObject = AddressSet.objects.get(firewall = firewall, zone = fromZoneObject, name = source)
									policyModel.srcAddressSet.add(sourceObject)
							for destination in policyData['destinations']:
								try:
									destinationObject = Address.objects.get(firewall = firewall, zone = toZoneObject, name = destination)
									policyObject.dstAddress.add(destinationObject)
								except:
									destinationObject = AddressSet.objects.get(firewall = firewall, zone = toZoneObject, name = destination)
									policyModel.dstAddressSet.add(destinationObject)
							for application in policyData['applications']:
								try:
									applicationObject = Application.objects.get(firewall = firewall, name = application)
									policyObject.application.add(applicationObject)
								except:
									applicationObject = ApplicationSet.objects.get(firewall = firewall, name = application)
									policyModel.applicationSet.add(applicationObject)

	return render_to_response( "rulemaker/index.html", {'data' : data} )