from django import template
from django.conf import settings
register = template.Library()

# the profile menu: profile, settings, logout etc.
def rulemaker_sidebar():

	menu = []

	menu.append({
		'title': 'Firewall rule maker',
		'link': '/network/rulemaker/',
	})

	return { 'menu': menu }

register.inclusion_tag('rulemaker/rulemaker_sidebar.html')(rulemaker_sidebar)
