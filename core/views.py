import pyotp
import base64
import random
import stripe
import string
import smtplib
from datetime import datetime
from django.conf import settings
from django.utils import timezone
from django.contrib import messages
from email.mime.text import MIMEText
from django.utils.html import escape
from django.core.mail import send_mail
from .forms import CheckoutForm,PaymentForm
from django.contrib.auth import logout as logoff
from django.contrib.auth import login, authenticate
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User as off_user
from django.contrib.auth.forms import AuthenticationForm 
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.views.generic import ListView, DetailView, View
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.hashers import make_password, check_password
from .forms import ItemSubmitForm, NewUserForm, UpdateProfileForm, SellerForm
from .models import Item, OrderItem, Order, Address, Payment, UserProfile, User

stripe.api_key = settings.STRIPE_SECRET_KEY

def create_ref_code():
	return ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))


def products(request):
	return render(request, "products.html", context = {'items': Item.objects.all()})

def is_valid_form(values):
	valid = True
	for field in values:
		if field == '':
			valid = False
	return valid

def otp_check(request):
	if request.method=="POST":
		password = escape(request.POST.get('password'))
		username = escape(request.POST.get('username'))
		email = escape(request.POST.get('email'))
		first_name = escape(request.POST.get('first_name'))
		last_name = escape(request.POST.get('last_name'))
		is_seller = escape(request.POST.get('is_seller'))

		otp = escape(request.POST.get('otp'))
		if is_seller is None:
			is_seller=False
		keygen = generateKey()
		key = base64.b32encode(keygen.returnValue(email).encode())
		OTP = pyotp.TOTP(key,interval = 400)
		print(OTP.now())
		if OTP.verify(otp):
			try:
				my_user = User(username=username, email=email, password=password, first_name = first_name, last_name = last_name, is_seller = is_seller)
				official_user =  off_user.objects.create_user(username=username, email=email, password=password, first_name = first_name, last_name = last_name,)
				'''here the password in this auth.user is useless'''
				my_user.user =official_user
				my_user.save()
				messages.success(request, "Registration successful." )
				return redirect("/")
			except Exception as e: 
				messages.error(request, e)
				return redirect("/register/")
		else:
			messages.error(request, "Unsuccessful registration. Invalid OTP.")
			form = NewUserForm(request.POST)
			return render(request=request, template_name='register.html', context={'register_form':form})
	else:
		return render(request=request, template_name='otp.html')

class generateKey:
	@staticmethod
	def returnValue(phone):
		return str(phone) + str(datetime.date(datetime.now())) + "Some Random Secret Key"

def register_request(request):
	if request.method == "POST":
		form = NewUserForm(request.POST)
		if form.is_valid():
			pswd = make_password(str(form.cleaned_data['password1']))
			keygen = generateKey()
			key = base64.b32encode(keygen.returnValue(form.cleaned_data['email']).encode())  # Key is generated
			OTP = pyotp.TOTP(key,interval = 400) 
			print("otp ",OTP.now())
			port = 465 
			password = "themostawesompassword"
			sender_email = "apkidukaannaarp@gmail.com"
			first_name = form.cleaned_data['first_name']
			last_name = form.cleaned_data['last_name']
			receiver_email = form.cleaned_data['email']
			message = MIMEText("Hi "+first_name +" "+last_name+"\n\n" + str(OTP.now()) + " is your login OTP")
			message['Subject'], message['From'], message['To'] = 'Login OTP', sender_email, receiver_email
			server = smtplib.SMTP_SSL("smtp.gmail.com", port)
			server.login(sender_email, password)
			server.sendmail(sender_email, [receiver_email], message.as_string())
			server.quit()
			is_seller = form.cleaned_data['is_seller']
			return render(request=request, template_name='otp.html',context={'email': receiver_email, 'password':pswd, 'username':str(form.cleaned_data['username']),'first_name':first_name, 'last_name':last_name, "is_seller":is_seller, 'form':form})
		else:
			messages.error(request, form.errors)
			form = NewUserForm(request.POST)
			return render (request=request, template_name='register.html', context={'register_form':form})
	else:
		form = NewUserForm(request.POST)
		return render (request=request, template_name='register.html', context={'register_form':form})

@login_required
def update_profile(request):
	if request.method == "POST":
		form = UpdateProfileForm(request.POST)
		username = request.user.username
		user = User.get_customer_by_id(username)
		email = user.email
		if check_password(request.POST.get('password1'), user.password):
			print('upadteeee')
			pswd = make_password(str(request.POST.get('password1')))
			keygen = generateKey()
			key = base64.b32encode(keygen.returnValue(email).encode())  # Key is generated
			OTP = pyotp.TOTP(key,interval = 400) 
			print("otp confirm ",OTP.now())
			port = 465 
			password = "themostawesompassword"
			sender_email = "apkidukaannaarp@gmail.com"
			first_name = request.POST.get('first_name')
			last_name = request.POST.get('last_name')
			receiver_email = str(email)
			print("|"+receiver_email + "|")
			print("|"+sender_email + "|")
			message = MIMEText("Hi "+first_name +" "+last_name+"\n\n" + str(OTP.now()) + " is your update profile OTP")
			message['Subject'], message['From'], message['To'] = 'Update Profile OTP', sender_email, str(receiver_email)
			server = smtplib.SMTP_SSL("smtp.gmail.com", port)
			server.login(sender_email, password)
			server.sendmail(sender_email, [receiver_email], message.as_string())
			server.quit()
			return render(request=request, template_name='updateotp.html',context={'email': receiver_email, 'password':pswd, 'username':username,'first_name':first_name, 'last_name':last_name, 'form':form})
		else:
			messages.error(request, form.errors)
			form = UpdateProfileForm(request.POST)
			return render (request=request, template_name='updateprofile.html', context={'update_profile_form':form})
	else:
		form = UpdateProfileForm()
		return render(request=request, template_name='updateprofile.html', context={'update_profile_form':form})

def update_otp_check(request):
	if request.method=="POST":
		password = escape(request.POST.get('password'))
		username = escape(request.POST.get('username'))
		email = escape(request.POST.get('email'))
		first_name = escape(request.POST.get('first_name'))
		last_name = escape(request.POST.get('last_name'))
		otp = escape(request.POST.get('otp'))
		keygen = generateKey()
		key = base64.b32encode(keygen.returnValue(email).encode())
		OTP = pyotp.TOTP(key,interval = 400)  # TOTP Model 
		print(OTP.now())
		if OTP.verify(otp):
			try:
				print('going to update')
				my_user = User.get_customer_by_id(username)
				official_user = off_user.objects.get(username=username)
				official_user.first_name = first_name
				official_user.last_name = last_name
				official_user.save()
				my_user.first_name = first_name
				my_user.last_name = last_name
				my_user.save()
				print('updated')
				messages.success(request, "Profile Updated Successfully." )
				return redirect("/")
			except Exception as e: 
				messages.error(request, e)
				return redirect("/update_profile/")
		else:
			messages.error(request, "Unsuccessful registration. Invalid OTP.")
			form = UpdateProfileForm(request.POST)
			return render(request=request, template_name='updateprofile.html', context={'update_profile_form':form})
	else:
		return render(request=request, template_name='updateotp.html')

def login_request(request):
	if request.method == "POST":
		usrname = escape(request.POST.get('username'))
		try:
			temp_user = User.get_customer_by_id(usrname)
			print(temp_user.username,temp_user.password)
			if check_password(request.POST.get('password'), temp_user.password):
				request.session['User'] = temp_user.username
				temp_off_user = authenticate(username = temp_user.username, password = temp_user.password)
				login(request, temp_off_user)
				messages.success(request, f"You are now logged in as {temp_user.username}.")
				bool_value= temp_user.get_is_seller()
				if bool_value == "True":
					request.session['is_seller'] = bool("True")
					request.session['is_verified'] = temp_user.get_is_verified()
					request.session['is_pdf_uploaded'] = temp_user.is_pdf_uploaded
					form = SellerForm(request.POST, request.FILES)
					return render(request=request, template_name="seller.html", context={"seller_form":form})		
				else:
					request.session['is_seller'] = bool("")
					return redirect('/')
			else:
				messages.error(request,"Invalid username or password.")
				form = AuthenticationForm(request.POST)
				return render(request=request, template_name="signin.html", context={"login_form":form})
		except Exception as e:
			messages.error(request,"Invalid username or password.")
			form = AuthenticationForm(request.POST)
			return render(request=request, template_name="signin.html", context={"login_form":form})
	else:
		form = AuthenticationForm()
		return render(request=request, template_name="signin.html", context={"login_form":form})


@login_required
def profile(request):
	username = None
	if request.user.is_authenticated:
		username = request.user.username
		user = User.get_customer_by_id(username)
		bool_value= user.get_is_seller()
		request.session['is_verified'] = user.get_is_verified()
		request.session['is_pdf_uploaded'] = user.is_pdf_uploaded
		request.session['username'] = user.username
		request.session['first_name'] = user.first_name
		request.session['last_name'] = user.last_name
		request.session['email'] = user.email
		print(user.first_name)
		print(user.last_name)
		if bool_value == "True":
			request.session['is_seller'] = bool("True")
			return render(request=request, template_name="profile.html")
		else:
			request.session['is_seller'] = bool("")
			return render(request=request, template_name="profile.html")

def seller(request):
	if request.method == 'POST':
		form = SellerForm(request.POST, request.FILES)
		if form.is_valid():
			username = escape(request.POST.get('username'))
			user = User.get_customer_by_id(username)
			user.pdf_file = request.FILES['pdf_file']
			user.is_pdf_uploaded = True
			user.save()
			bool_value= user.get_is_seller()
			if bool_value == "True":
				request.session['is_seller'] = bool("True")
				request.session['is_verified'] = user.get_is_verified()
				request.session['is_pdf_uploaded'] = True
				return render(request=request, template_name="seller.html", context={"seller_form":form})
			else:
				request.session['is_seller'] = bool("")
				request.session['is_verified'] = user.get_is_verified()
				request.session['is_pdf_uploaded'] = user.is_pdf_uploaded
				return redirect('/')
		else:
			form = SellerForm(request.POST, request.FILES)
			return render(request=request, template_name="seller.html", context={"seller_form":form})
	else:
		form = SellerForm(request.POST, request.FILES)
		return render(request=request, template_name="seller.html", context={"seller_form":form})

@login_required
def UploadItem(request):
	form=ItemSubmitForm(request.POST, request.FILES)
	if request.method == 'POST':
		if form.is_valid():
			username = escape(request.POST.get('username'))
			title = escape(request.POST.get('title'))
			price = escape(request.POST.get('price'))
			discount_price = escape(request.POST.get('discount_price'))
			category = escape(request.POST.get('category'))
			label = escape(request.POST.get('label'))
			slug = escape(request.POST.get('slug'))
			description = escape(request.POST.get('description'))
			image = request.FILES['image']
			image2 = request.FILES['image2']
			temp_user = request.user
			user = User.get_customer_by_id(temp_user.username)
			new_item = Item(title=title, price=price, discount_price=discount_price, category=category, label=label,
			slug=slug, description=description, image=image, image2=image2, seller=user)

			new_item.save()
			messages.success(request, 'Your Item has been added!')
			form=ItemSubmitForm(request.POST, request.FILES)
			return render(request=request, template_name="seller.html", context={"item_upload_form":form})
		else:
			form=ItemSubmitForm(request.POST, request.FILES)
			return render(request=request, template_name="upload.html", context={"item_upload_form":form})	
	else:
		form=ItemSubmitForm(request.POST, request.FILES)
		return render(request=request, template_name="upload.html", context={"item_upload_form":form})

def logout(request):
	request.session.clear()
	logoff(request)
	messages.success(request, "You have signed out.")
	return redirect('/')

class CheckoutView(View):
	def get(self, *args, **kwargs):
		try:
			temp_user = self.request.user
			user = User.get_customer_by_id(temp_user.username)
			if user.is_seller:
				raise Exception('You cannot add item to cart')
			order = Order.objects.get(user=self.request.user, ordered=False)
			print(order)
			form = CheckoutForm()
			context = {'form': form,'order': order}
			shipping_address_qs = Address.objects.filter(
				user=self.request.user,
				address_type='S',
				default=True)
			if shipping_address_qs.exists():
				context.update(
					{'default_shipping_address': shipping_address_qs[0]})
			return render(self.request, "checkout.html", context)
		except ObjectDoesNotExist:
			messages.info(self.request, "You do not have an active order")
			return redirect("/")
		except Exception as e:
			messages.error(self.request, "Login in first")
			return redirect('/signin/')
		
	def post(self, *args, **kwargs):
		form = CheckoutForm(self.request.POST or None)
		try:
			order = Order.objects.get(user=self.request.user, ordered=False)
			if form.is_valid():
				use_default_shipping = form.cleaned_data.get('use_default_shipping')
				print(use_default_shipping)
				if use_default_shipping:
					print("Using the defualt shipping address")
					address_qs = Address.objects.filter(
						user=self.request.user,
						address_type='S',
						default=True)

					if address_qs.exists():
						shipping_address = address_qs[0]
						order.shipping_address = shipping_address
						order.save()
					else:
						messages.info(self.request, "No default shipping address available")
						return redirect('core:checkout')
				else:
					print("User is entering a new shipping address")
					shipping_address1 = form.cleaned_data.get('shipping_address')
					shipping_address2 = form.cleaned_data.get('shipping_address2')
					shipping_country = form.cleaned_data.get('shipping_country')
					shipping_zip = form.cleaned_data.get('shipping_zip')
					if is_valid_form([shipping_address1, shipping_country, shipping_zip]):
						shipping_address = Address( user=self.request.user, street_address=shipping_address1, apartment_address=shipping_address2, country=shipping_country, zip=shipping_zip, address_type='S')
						shipping_address.save()
						order.shipping_address = shipping_address
						order.save()
						set_default_shipping = form.cleaned_data.get('set_default_shipping')
						if set_default_shipping:
							shipping_address.default = True
							shipping_address.save()
					else:
						messages.info(self.request, "Please fill in the required shipping address fields")
				payment_option = form.cleaned_data.get('payment_option')
				if payment_option == 'S':
					return redirect('core:payment', payment_option='stripe')
				else:
					messages.warning(self.request, "Invalid payment option selected")
					return redirect('core:checkout')
		except ObjectDoesNotExist:
			messages.warning(self.request, "You do not have an active order")
			return redirect("core:order-summary")

class PaymentView(View):
	def get(self, *args, **kwargs):
		try:
			temp_user = self.request.user
			user = User.get_customer_by_id(temp_user.username)
			if user.is_seller:
				raise Exception('You cannot add item to cart')
			order = Order.objects.get(user=self.request.user, ordered=False)
			if order.shipping_address:
				context = {
					'order': order,
					'STRIPE_PUBLIC_KEY': settings.STRIPE_PUBLIC_KEY
				}
				userprofile = self.request.user.userprofile
				if userprofile.one_click_purchasing:
					cards = stripe.Customer.list_sources(
						userprofile.stripe_customer_id,
						limit=3,
						object='card'
					)
					card_list = cards['data']
					if len(card_list) > 0:
						context.update({'card': card_list[0]})
				return render(self.request, "payment.html", context)
			else:
				messages.warning(
					self.request, "You have not added a shipping address")
				return redirect("core:checkout")
		except Exception as e:
			messages.error(self.request, "Not Possible.")
			return redirect('/')

	def post(self, *args, **kwargs):
		order = Order.objects.get(user=self.request.user, ordered=False)
		form = PaymentForm(self.request.POST)
		userprofile = UserProfile.objects.get(user=self.request.user)
		if form.is_valid():
			token = form.cleaned_data.get('stripeToken')
			save = form.cleaned_data.get('save')
			use_default = form.cleaned_data.get('use_default')
			if save:
				if userprofile.stripe_customer_id != '' and userprofile.stripe_customer_id is not None:
					customer = stripe.Customer.retrieve(
						userprofile.stripe_customer_id)
					customer.sources.create(source=token)
				else:
					customer = stripe.Customer.create(email=self.request.user.email,)
					customer.sources.create(source=token)
					userprofile.stripe_customer_id = customer['id']
					userprofile.one_click_purchasing = True
					userprofile.save()
			amount = int(order.get_total() * 100)
			try:
				if use_default or save:
					charge = stripe.Charge.create( amount=amount, currency="inr", customer=userprofile.stripe_customer_id)
				else:
					charge = stripe.Charge.create( amount=amount, currency="inr",source=token)

				payment = Payment()
				payment.stripe_charge_id = charge['id']
				payment.user = self.request.user
				payment.amount = order.get_total()
				payment.save()
				order_items = order.items.all()
				order_items.update(ordered=True)
				for item in order_items:
					item.save()
				order.ordered = True
				order.payment = payment
				order.ref_code = create_ref_code()
				order.save()
				
				print(order)
				temp_msg = "Hello, " + self.request.user.first_name + " " + self.request.user.last_name + ". \n Your Order has been placed with order ID " + order.ref_code + ", please fine the details below: \n"
				temp_msg += '\n Total Amount: Rs ' + str(order.get_total()) + '/- \n Thank You for shopping with us. \n #apnidukan'

				send_mail(
					subject = 'Order Placed! Thanks for shopping with us!',
					message = temp_msg,
					from_email = 'apkidukaannaarp@gmail.com',
					recipient_list=[self.request.user.email],
					fail_silently=True,
				)
				messages.success(self.request, "Your order was successful!")
				return redirect("/")

			except stripe.error.CardError as e:
				body = e.json_body
				err = body.get('error', {})
				messages.warning(self.request, f"{err.get('message')}")
				return redirect("/")
			except stripe.error.RateLimitError as e:
				messages.warning(self.request, "Rate limit error")
				return redirect("/")
			except stripe.error.InvalidRequestError as e:
				print(e)
				messages.warning(self.request, "Invalid parameters")
				return redirect("/")
			except stripe.error.AuthenticationError as e:
				messages.warning(self.request, "Not authenticated")
				return redirect("/")
			except stripe.error.APIConnectionError as e:
				messages.warning(self.request, "Network error")
				return redirect("/")
			except stripe.error.StripeError as e:
				messages.warning(
					self.request, "Something went wrong. You were not charged. Please try again.")
				return redirect("/")
			except Exception as e:
				print(e)
				messages.warning(
					self.request, "A serious error occurred. We have been notifed.")
				return redirect("/")
		messages.warning(self.request, "Invalid data received")
		return redirect("/payment/stripe/")

def FilterView(request):
	if request.METHOD == 'POST':
		if "SW" in request.GET:
			print("Here")
			return redirect("/")
		print("There")
		return redirect("/")

class HomeView(ListView):
	model = Item
	paginate_by = 10
	template_name = "start.html"
	
class OrderSummaryView(LoginRequiredMixin,View):
	def get(self, *args, **kwargs):
		try:
			print("here",self.request.user)
			order = Order.objects.get(user=self.request.user, ordered=False)
			# print(order)
			# print('|' + order + '|') 
			context = {'object': order}
			return render(self.request, 'order_summary.html', context)
		except ObjectDoesNotExist:
			messages.warning(self.request, "You do not have an active order")
			return redirect("/")


class ItemDetailView(DetailView):
	model = Item
	template_name = "product.html"

@login_required
def order_history(request):
	try:
		all_orders = Order.objects.filter(user=request.user, ordered=True)
		return render(request, template_name="order_history.html", context={'all_orders': all_orders, 'is_order':True})
	except ObjectDoesNotExist:
		messages.warning(request, "You do not have any orders")
		return redirect("/")		

@login_required
def seller_items(request):
	try:
		temp_user = request.user
		user = User.get_customer_by_id(temp_user.username)
		all_items = Item.objects.filter(seller=user)
		print(all_items)
		return render(request, template_name="seller_items.html", context={'all_items': all_items, 'is_seller':user.is_seller})
	except ObjectDoesNotExist:
		messages.warning(request, "You do not have any items uploaded")
		return redirect("/")		

@login_required
def add_to_cart(request, slug):
	try:
		temp_user = request.user
		user = User.get_customer_by_id(temp_user.username)
		if user.is_seller:
			raise Exception('You cannot add item to cart')
		item = get_object_or_404(Item, slug=slug)
		order_item, created = OrderItem.objects.get_or_create(item=item,user=request.user,ordered=False)
		order_qs = Order.objects.filter(user=request.user, ordered=False)
		if order_qs.exists():
			order = order_qs[0]
			if order.items.filter(item__slug=item.slug).exists():
				order_item.quantity += 1
				order_item.save()
				messages.info(request, "This item quantity was updated.")
				return redirect("core:order-summary")
			else:
				order.items.add(order_item)
				messages.info(request, "This item was added to your cart.")
				return redirect("core:order-summary")
		else:
			ordered_date = timezone.now()
			order = Order.objects.create(
				user=request.user, ordered_date=ordered_date)
			order.items.add(order_item)
			messages.info(request, "This item was added to your cart.")
			return redirect("core:order-summary")
	except Exception as e:
		messages.error(request, e)
		return redirect('/')

@login_required
def remove_from_cart(request, slug):
	try:
		temp_user = request.user
		user = User.get_customer_by_id(temp_user.username)
		if user.is_seller:
			raise Exception('You cannot add item to cart')
		item = get_object_or_404(Item, slug=slug)
		order_qs = Order.objects.filter(user=request.user,ordered=False)
		if order_qs.exists():
			order = order_qs[0]
			if order.items.filter(item__slug=item.slug).exists():
				order_item = OrderItem.objects.filter(item=item,user=request.user,ordered=False)[0]
				order.items.remove(order_item)
				order_item.delete()
				messages.info(request, "This item was removed from your cart.")
				return redirect("core:order-summary")
			else:
				messages.info(request, "This item was not in your cart")
				return redirect("core:product", slug=slug)
		else:
			messages.info(request, "You do not have an active order")
			return redirect("core:product", slug=slug)
	except Exception as e:
		messages.error(request, e)
		return redirect('/')


@login_required
def remove_single_item_from_cart(request, slug):
	try:
		temp_user = request.user
		user = User.get_customer_by_id(temp_user.username)
		if user.is_seller:
			raise Exception('You cannot add item to cart')
		item = get_object_or_404(Item, slug=slug)
		order_qs = Order.objects.filter(user=request.user,ordered=False)
		if order_qs.exists():
			order = order_qs[0]
			if order.items.filter(item__slug=item.slug).exists():
				order_item = OrderItem.objects.filter(item=item,user=request.user,ordered=False)[0]
				if order_item.quantity > 1:
					order_item.quantity -= 1
					order_item.save()
				else:
					order.items.remove(order_item)
				messages.info(request, "This item quantity was updated.")
				return redirect("core:order-summary")
			else:
				messages.info(request, "This item was not in your cart")
				return redirect("core:product", slug=slug)
		else:
			messages.info(request, "You do not have an active order")
			return redirect("core:product", slug=slug)
	except Exception as e:
		messages.error(request, e)
		return redirect('/')

@login_required
def search(request):
	try:
		print("here",request.POST)
		searched =request.POST['searched']
		print("now",searched)
		if searched == "Smart Watches":
			valid_products = Item.objects.filter(category = "SW")
		elif searched == "Audio Gear":
			valid_products = Item.objects.filter(category = "AG")
		elif searched == "Voice Assistants":
			valid_products = Item.objects.filter(category = "VA")
		elif searched == "Phones":
			valid_products = Item.objects.filter(category = "P")
		elif searched == "Laptops":	
			valid_products = Item.objects.filter(category = "L")
		elif searched == "Cameras":
			valid_products = Item.objects.filter(category = "C")
		else:
			valid_products = Item.objects.filter(title = searched )
			if valid_products:
				context ={ 'object_list': valid_products}
				return render(request,template_name="search_item.html",context =context)
			else:
				messages.warning(request, "Invalid Search!!, Please try with a valid query")
				return redirect("/")
		context ={ 'object_list': valid_products}
		return render(request,template_name="search_item.html", context = context)
	except Exception as e:
		print(e)
		body = request.body.decode("utf-8")
		if 'searched=' in body:
			searched = body.split("searched=")[1]
			searched = searched.replace("+"," ")
		else:
			searched =""
		print("--", searched, "--")
		return render(request,template_name="search_item.html",context ={'searched' : searched})
