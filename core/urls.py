from django.urls import path

from .views import ( ItemDetailView, CheckoutView, HomeView, OrderSummaryView, add_to_cart, register_request, remove_from_cart, remove_single_item_from_cart, PaymentView, otp_check, login_request,  logout, seller, profile, UploadItem, update_otp_check, update_profile, order_history, seller_items, seller_items, search)

app_name = 'core'

urlpatterns = [
    path('otp/', otp_check, name='otp'),
    path('seller/', seller, name='seller'),
    path('search/', search, name='search'),
    path('signout/', logout, name='signout'),
    path('profile/', profile, name='profile'),
    path('upload/', UploadItem, name='upload'),
    path('', HomeView.as_view(), name='start'),
    path('signin/', login_request, name='signin'),
    path('register/', register_request, name='register'),
    path('updateotp/', update_otp_check, name='updateotp'),
    path('seller_items/', seller_items, name='seller_items'),
    path('checkout/', CheckoutView.as_view(), name='checkout'),
    path('order_history/', order_history, name='order_history'),
    path('add-to-cart/<slug>/', add_to_cart, name='add-to-cart'),
    path('update_profile/', update_profile, name='update_profile'),
    path('product/<slug>/', ItemDetailView.as_view(), name='product'),
    path('payment/<payment_option>/', PaymentView.as_view(), name='payment'),
    path('order-summary/', OrderSummaryView.as_view(), name='order-summary'),
    path('remove-from-cart/<slug>/', remove_from_cart, name='remove-from-cart'),
    path('remove-item-from-cart/<slug>/', remove_single_item_from_cart, name='remove-single-item-from-cart'),
]
