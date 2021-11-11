from django.contrib import admin
from .models import Item, OrderItem, Order, Payment, Address, UserProfile
from .models import User

admin.site.register(User)

class OrderAdmin(admin.ModelAdmin):
    list_display = ['user', 'ordered', 'received', 'shipping_address', 'payment',]
    list_display_links = [ 'user', 'shipping_address', 'payment',]
    list_filter = ['ordered']
    search_fields = ['user__username']


class AddressAdmin(admin.ModelAdmin):
    list_display = [ 'user', 'street_address', 'apartment_address', 'country', 'zip', 'address_type', 'default']
    list_filter = ['default', 'address_type', 'country']
    search_fields = ['user', 'street_address', 'apartment_address', 'zip']


admin.site.register(Item)
admin.site.register(OrderItem)
admin.site.register(Order, OrderAdmin)
admin.site.register(Payment)
admin.site.register(Address, AddressAdmin)
admin.site.register(UserProfile)
