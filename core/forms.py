from django import forms
from django_countries.fields import CountryField
from django_countries.widgets import CountrySelectWidget
from django.contrib.auth.forms import UserCreationForm
from django.core.validators import FileExtensionValidator
from .models import CATEGORY_CHOICES, LABEL_CHOICES
from .models import User, Item

PAYMENT_CHOICES = ( ('S', 'Stripe'),)

class ItemSubmitForm(forms.Form):
    title = forms.CharField(max_length=100, required=True)
    price = forms.FloatField(required=True)
    discount_price = forms.FloatField(required=True)
    category = forms.ChoiceField(choices=CATEGORY_CHOICES, required=True)
    label = forms.ChoiceField(choices=LABEL_CHOICES, required=True)
    slug = forms.CharField(max_length=50, required=True)
    description = forms.CharField(required=False)
    image = forms.ImageField(required=True, validators=[FileExtensionValidator(allowed_extensions=['png', 'jpg', 'jpeg', 'jfif'])])
    image2 = forms.ImageField(required=True)
    class Meta:
            model = Item
            fields = ('title', 'price', 'discount_price', 'category', 'label', 'slug', 'description', 'image', 'image2')

class SellerForm(forms.Form):
    pdf_file = forms.FileField(label = 'Upload the documents.', required=True, validators=[FileExtensionValidator(allowed_extensions=['pdf'])])

    class Meta:
        model = User
        fields = ('pdf_file')

class UpdateProfileForm(UserCreationForm):
    first_name = forms.CharField(required=True)
    last_name = forms.CharField(required=True)
    class Meta:
        model = User
        fields = ("first_name","last_name", "password1")

    def save(self, commit=True):
        user = super(UpdateProfileForm, self).save(commit=False)
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        if commit:
            user.save()
        return user

class NewUserForm(UserCreationForm):
    first_name = forms.CharField(required=True)
    last_name = forms.CharField(required=True)
    email = forms.EmailField(required=True)
    is_seller = forms.BooleanField(required=False)
    is_seller.label = "Are You a Seller?"    
    email.help_text = 'Please choose this carefully, this cannot be changed in future'
    
    def __init__(self, *args, **kwargs):
        super(NewUserForm, self).__init__(*args, **kwargs)
        self.fields['username'].help_text = 'Please choose this carefully, this cannot be changed in future'

    class Meta:
        model = User
        fields = ( "first_name","last_name","username", "email","password1", "password2", "is_seller")

    def save(self, commit=True):
        user = super(NewUserForm, self).save(commit=False)
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        user.is_seller = self.cleaned_data['is_seller']
        if commit:
            user.save()
        return user


class CheckoutForm(forms.Form):
    shipping_address = forms.CharField(required=True)
    shipping_address2 = forms.CharField(required=False)
    shipping_country = CountryField(blank_label='(select country)').formfield(
        required=True,
        widget=CountrySelectWidget(attrs={'class': 'custom-select d-block w-100',}))
    shipping_zip = forms.IntegerField(required=True)
    set_default_shipping = forms.BooleanField(required=False)
    use_default_shipping = forms.BooleanField(required=False)

    payment_option = forms.ChoiceField(
        widget=forms.RadioSelect, choices=PAYMENT_CHOICES)


class PaymentForm(forms.Form):
    stripeToken = forms.CharField(required=False)
    save = forms.BooleanField(required=False)
    use_default = forms.BooleanField(required=False)
