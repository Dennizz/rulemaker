from django.conf.urls import patterns, include, url
from views import *

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    url(r'^$',  index,         name='index'),

    url(r'^ruleoverview/(?P<firewall>[^/]+)', ruleOverview, name='ruleOverview'),
    url(r'^zoneoverview/(?P<firewall>[^/]+)', zoneOverview, name='zoneOverview'),
    url(r'^updatefirewall/(?P<firewall>[^/]+)', updateFirewall, name='updateFirewall'),

    url(r'^addressbook/(?P<firewall>[^/]+)/(?P<zone>[^/]+)', zoneAddressbook, name='zoneAddressbook'),

    url(r'^address/(?P<firewall>[^/]+)/(?P<zone>[^/]+)/(?P<address>[^/]+)', viewAddress, name='viewAddress'),

    url(r'^addressSet/(?P<firewall>[^/]+)/(?P<zone>[^/]+)/(?P<addressSet>[^/]+)', viewAddressSet, name='viewAddressSet'),
    url(r'^application/(?P<firewall>[^/]+)/(?P<application>[^/]+)', viewApplication, name='viewApplication'),
    url(r'^applicationSet/(?P<firewall>[^/]+)/(?P<applicationSet>[^/]+)', viewApplicationSet, name='viewApplicationSet'),
)
