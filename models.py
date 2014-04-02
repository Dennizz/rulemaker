from django.db import models

# Create your models here.

class Firewall(models.Model):
	hostname	=   models.CharField(max_length=256)
	username	=	models.CharField(max_length=256)
	location	=	models.CharField(max_length=256)
	def __unicode__(self):
		return  unicode(self.hostname)

class Zone(models.Model):
	firewall	=	models.ForeignKey(Firewall)
	name		=	models.CharField(max_length=256)
	def __unicode__(self):
		return  unicode(self.name)

class Address(models.Model):
	firewall	=	models.ForeignKey(Firewall)
	zone		=	models.ForeignKey(Zone, related_name='zoneAddress')
	name		=	models.CharField(max_length=256)
	address		=	models.GenericIPAddressField()
	netmaskLength	=	models.IntegerField()
	def __unicode__(self):
		return  unicode(self.name) + "\t" + unicode(self.zone)

class AddressSet(models.Model):
	firewall	=	models.ForeignKey(Firewall)
	addresses	=	models.ManyToManyField(Address, null=True, blank=True)
	zone		=	models.ForeignKey(Zone, related_name='zoneAddressSet')
	name		=	models.CharField(max_length=256)
	def __unicode__(self):
		return  unicode(self.name)

class Application(models.Model):
	firewall	=	models.ForeignKey(Firewall)
	name		=   models.CharField(max_length=256)
	def __unicode__(self):
		return  unicode(self.name)

class ApplicationPort(models.Model):
	application	=	models.ForeignKey(Application)
	firewall	=	models.ForeignKey(Firewall)
	destPort	=	models.CharField(max_length=256, blank=True, null=True)	
	protocol	=	models.CharField(max_length=256)
	def __unicode__(self):
		return  unicode(self.application) + "\t" + unicode(self.destPort) + "\t" + unicode(self.destPort)
		
class ApplicationSet(models.Model):
	firewall	=	models.ForeignKey(Firewall)
	applications=	models.ManyToManyField(Application, null=True, blank=True)
	name		=	models.CharField(max_length=256)
	def __unicode__(self):
		return  unicode(self.name)

class Policy(models.Model):
	firewall	=	models.ForeignKey(Firewall)
	name		=	models.CharField(max_length=256)
	state		=	models.CharField(max_length=256) #needs to be converted to a choice or bool field for states active/inactive	
	action		=	models.CharField(max_length=256) #needs to be converted to a choice or bool field for actions permit, deny, drop
	fromZone	=	models.ForeignKey(Zone, related_name='fromZone')
	toZone		=	models.ForeignKey(Zone, related_name='toZone')
	srcAddress	=	models.ManyToManyField(Address, null=True, blank=True, related_name='srcAddress')
	srcAddressSet	=	models.ManyToManyField(AddressSet, null=True, blank=True, related_name='srcAddressSet')
	dstAddress	=	models.ManyToManyField(Address, null=True, blank=True, related_name='dstAddress')
	dstAddressSet	=	models.ManyToManyField(AddressSet, null=True, blank=True, related_name='dstAddressSet')
	application	=	models.ManyToManyField(Application, null=True, blank=True)
	applicationSet	=	models.ManyToManyField(ApplicationSet, null=True, blank=True)
	def __unicode__(self):
		return  unicode(self.name)

class ExcludeZone(models.Model):
	firewall	=	models.ForeignKey(Firewall)
	name		=	models.CharField(max_length=256)
	def __unicode__(self):
		return  unicode(self.name)