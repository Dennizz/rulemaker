from django import forms

class RuleOverviewForm(forms.Form):
	fromzone =  forms.ChoiceField( choices=(),widget=forms.Select(attrs={}), label="From Zone" )
	tozone   =  forms.ChoiceField( choices=(),widget=forms.Select(attrs={}), label="To Zone" )
