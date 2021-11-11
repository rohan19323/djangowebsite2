from django.db.models.signals import post_save
from django.conf import settings
from django.db import models
from django.shortcuts import reverse
from django_countries.fields import CountryField
from django.db import models
from django.contrib.auth.models import User as off_user

class User(models.Model):
    username = models.CharField(max_length=150, primary_key=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=500)
    is_seller = models.BooleanField(default =False)
    is_verified = models.BooleanField(default =False)
    is_pdf_uploaded = models.BooleanField(default=False)
    pdf_file = models.FileField(upload_to='static/', null=True, blank=True)
    user = models.OneToOneField(off_user, on_delete=models.CASCADE)
    USERNAME_FIELD = 'username'

    def register(self):
        self.save()
    
    @staticmethod
    def get_customer_by_email(email):
        try:
            return User.objects.get(email=email)
        except:
            return False

    def get_is_seller(self):
        return str(self.is_seller)

    def get_is_verified(self):
        return self.is_verified

    @staticmethod
    def get_customer_by_id(ids):
        return User.objects.get(username=ids)

    @staticmethod
    def get_customer_by_session_id(ids):
        return User.objects.get(id__in=ids)

    def isExists(self):
        if User.objects.filter(username = self.username):
            return True
        return  False

CATEGORY_CHOICES = ( ('SW', 'Smart Watches'), ('AG', 'Audio Gear'), ('VA', 'Voice Assistants'), ('P', 'Phones'), ('L', 'Laptops'), ('C', 'Cameras') )

LABEL_CHOICES = ( ('P', 'New'), ('S', 'Few Left'), ('D', 'Limited Period Offer'))

ADDRESS_CHOICES = ( ('S', 'Shipping') ,)


class UserProfile(models.Model):
    user = models.OneToOneField(
    settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    stripe_customer_id = models.CharField(max_length=50, blank=True, null=True)
    one_click_purchasing = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username


class Item(models.Model):
    title = models.CharField(max_length=100)
    price = models.FloatField()
    discount_price = models.FloatField(blank=True, null=True)
    category = models.CharField(choices=CATEGORY_CHOICES, max_length=2)
    label = models.CharField(choices=LABEL_CHOICES, max_length=1)
    slug = models.CharField(max_length=50)
    description = models.TextField()
    image = models.ImageField(upload_to='static/')
    image2 = models.ImageField(upload_to='static/', null=True)
    seller = models.ForeignKey(User, on_delete = models.CASCADE)
    
    def __str__(self):
        return self.title

    @staticmethod
    def get_item_by_slug(slug):
        return Item.objects.get(slug=slug)
    
    def get_slug(self):
        return self.slug

    def get_absolute_url(self):
        return reverse("core:product", kwargs={ 'slug': self.slug })

    def get_add_to_cart_url(self):
        return reverse("core:add-to-cart", kwargs={ 'slug': self.slug })

    def get_remove_from_cart_url(self):
        return reverse("core:remove-from-cart", kwargs={ 'slug': self.slug })

    @staticmethod
    def get_all_products_by_id(category_id):
        if category_id:
            return Item.objects.filter(category = category_id)
        else:
            return Item.objects.all()



class OrderItem(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    ordered = models.BooleanField(default=False)
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)

    def __str__(self):
        return f"{self.quantity} of {self.item.title}"

    def get_total_item_price(self):
        return self.quantity * self.item.price

    def get_total_discount_item_price(self):
        return self.quantity * self.item.discount_price

    def get_amount_saved(self):
        return self.get_total_item_price() - self.get_total_discount_item_price()

    def get_final_price(self):
        if self.item.discount_price:
            return self.get_total_discount_item_price()
        return self.get_total_item_price()


class Order(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    items = models.ManyToManyField(OrderItem)
    start_date = models.DateTimeField(auto_now_add=True)
    ordered_date = models.DateTimeField()
    ordered = models.BooleanField(default=False)
    shipping_address = models.ForeignKey( 'Address', related_name='shipping_address', on_delete=models.SET_NULL, blank=True, null=True)
    payment = models.ForeignKey( 'Payment', on_delete=models.SET_NULL, blank=True, null=True)
    received = models.BooleanField(default=False)
    ref_code = models.CharField(max_length=20, blank=True, null=True)
    
    def __str__(self):
        return self.user.username

    def get_total(self):
        total = 0
        for order_item in self.items.all():
            total += order_item.get_final_price()
        return total


class Address(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    street_address = models.CharField(max_length=100)
    apartment_address = models.CharField(max_length=100)
    country = CountryField(multiple=False)
    zip = models.CharField(max_length=100)
    address_type = models.CharField(max_length=1, choices=ADDRESS_CHOICES)
    default = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username

    class Meta:
        verbose_name_plural = 'Addresses'


class Payment(models.Model):
    stripe_charge_id = models.CharField(max_length=50)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, blank=True, null=True)
    amount = models.FloatField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username


def userprofile_receiver(sender, instance, created, *args, **kwargs):
    if created:
        userprofile = UserProfile.objects.create(user=instance)


post_save.connect(userprofile_receiver, sender=settings.AUTH_USER_MODEL)
