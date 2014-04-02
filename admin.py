from django.contrib import admin
from rulemaker.models import *

# Register your models here.
admin.site.register(Firewall)
admin.site.register(Zone)
admin.site.register(ExcludeZone)
admin.site.register(Policy)
admin.site.register(Address)
admin.site.register(AddressSet)
admin.site.register(Application)
admin.site.register(ApplicationPort)
admin.site.register(ApplicationSet)
