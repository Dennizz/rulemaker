from django.conf.urls import patterns, include, url
from views import *

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    url(r'^ruleoverview/(?P<firewall>[^/]+)/(?P<srcZone>[^/]+)/(?P<dstZone>[^/]+)', ruleOverview, name='ruleOverview'),
    url(r'^updatefirewall/(?P<firewall>[^/]+)', updateFirewall, name='updateFirewall'),
)
