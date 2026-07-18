from django import forms

class URLForm(forms.Form):
    url = forms.URLField(
        label="",
        widget=forms.URLInput(attrs={
            "class": "form-control",
            "placeholder": "Enter URL"
        })
    )