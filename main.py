import bcrypt
import boto
import decimal
import os.path
import re
import rsa
import stripe
import time
import torndb
import tornado.httpserver
import tornado.ioloop
import tornado.web

from tornado.options import define, options


define("port", default=8000, help="run on the given port", type=int)
define("mysql_host", default="localhost", help="database host")
define("mysql_database", default="database_name", help="database name")
define("mysql_user", default="database_user", help="database user")
define("mysql_password", default="database_password", help="database password")


aws_key_pair_id = 'XXXXXXXXXXXXXXXXXXXX'
aws_priv_key_file ='pk-xxxxxxxxxxxxxxxxxxxx.pem'


EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    if email and EMAIL_RE.match(email):
        return email


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/login", LoginHandler),
            (r"/logout", LogoutHandler),
            (r"/register", RegisterHandler),
            (r"/video/([0-9]+)", VideoHandler),
            (r"/purchase/([a-zA-Z0-9-_]+)", PurchaseHandler),
            (r"/bucket", BucketHandler),
        ]
        settings = dict(
            site_title=u"Site Title",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            static_url_prefix="https://s3-us-west-2.amazonaws.com/assets/",
            xsrf_cookies=True,
            cookie_secret="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            login_url="/login",
            debug=False,
        )
        tornado.web.Application.__init__(self, handlers, **settings)

        self.db = torndb.Connection(
            host=options.mysql_host,
            database=options.mysql_database,
            user=options.mysql_user,
            password=options.mysql_password
        )
        
        self.cf = boto.connect_cloudfront()


class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db

    @property
    def cf(self):
        return self.application.cf

    def get_current_user(self):
        member_id = self.get_secure_cookie("member_id")
        if not member_id: return None
        return self.db.get("SELECT * FROM members WHERE id = %s", int(member_id))


class HomeHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        courses = self.db.query("SELECT purchases.*, wp_posts.post_title FROM purchases INNER JOIN wp_posts ON purchases.video_slug=wp_posts.post_name WHERE purchases.member_id=%s AND wp_posts.post_type='course'", self.current_user.id)
        self.render('index.html', courses=courses)


class LoginHandler(BaseHandler):
    def get(self):
        referer = '/'
        if self.request.headers.get('Referer'):
            referer = self.request.headers.get('Referer')
            if 'sitename' in referer and 'courses' in referer:
                ukis = referer.split('/')
                referer = '/purchase/' + ukis[5]
        self.render('login.html', email='', error_login='', hashed='', referer=referer)

    def post(self):
        have_error = False
        email = self.get_argument('email')
        password = self.get_argument('password')
        referer = self.get_argument('referer')

        hashed = ''
        member = self.db.get('SELECT * FROM members WHERE email=%s', email)

        if member and password:
            hashed = bcrypt.hashpw(password, member.password)
            if member.password == hashed:
                self.set_secure_cookie('member_id', str(member.id), expires_days=None, domain='.thedomain.com')
                self.redirect(referer)

        self.render('login.html', email=email, error_login='Invalid email or password.')


class LogoutHandler(BaseHandler):
    def get(self):
        referer = '/'
        if self.request.headers.get('Referer'):
            referer = self.request.headers.get('Referer')
        self.clear_cookie('member_id', domain='.thedomain.com')
        self.redirect(referer)


class RegisterHandler(BaseHandler):
    def get(self):
        referer = '/'
        if self.request.headers.get('Referer'):
            referer = self.request.headers.get('Referer')
            if 'sitename' in referer and 'courses' in referer:
                ukis = referer.split('/')
                referer = '/purchase/' + ukis[5]
        self.render('register.html', email='', error_email='', error_password1='', error_password2='', referer=referer)

    def post(self):
        have_error = False
        user_email = self.get_argument('email')
        password1 = self.get_argument("password1")
        password2 = self.get_argument("password2")
        referer = self.get_argument('referer')
        
        error_email = ''
        error_password1 = ''
        error_password2 = ''

        email = valid_email(user_email)
        if not email:
            email = user_email
            have_error = True
            error_email = "That's not a valid email."
        elif self.email_exists(email):
            have_error = True
            error_email = 'Email already exists.'
        else: 
            if not password1:
                have_error = True
                error_password1 = "Please enter a password."
            elif not password2:
                have_error = True
                error_password2 = "Please verify password."
            elif password1 != password2:
                have_error = True
                error_password2 = "Passwords do not match."

        if have_error == False:
            hashed = bcrypt.hashpw(password1, bcrypt.gensalt())
            member_id = self.db.execute("INSERT INTO members (email, password, date_registered) VALUES (%s, %s, UTC_TIMESTAMP())", email, hashed)
            self.set_secure_cookie('member_id', str(member.id), expires_days=None, domain='.thedomain.com')
            self.redirect(referer)

        self.render('register.html', email=email, error_email=error_email, error_password1=error_password1, error_password2=error_password2)

    def email_exists(self, email):
        return self.db.get('SELECT * FROM members WHERE email=%s', email)


class VideoHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, purchase_id):
        video = self.db.get("SELECT * FROM purchases INNER JOIN wp_posts ON purchases.video_slug=wp_posts.post_name WHERE purchases.id=%s AND wp_posts.post_type='course'", purchase_id)
        self.render('video.html', signed_url=video.signed_url, video_title=video.post_title)


class PurchaseHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, video_slug):
        video = self.db.get("SELECT post_title FROM wp_posts WHERE post_name=%s AND post_type='course'", video_slug)
        self.render('purchase.html', video_title=video.post_title, video_slug=video_slug, stripe_error='')

    def post(self, video_slug=''):
        # Set your secret key: remember to change this to your live secret key in production
        # See your keys here https://manage.stripe.com/account
        stripe.api_key = "sk_test_xxxxxxxxxxxxxxxxxxxxxxxx"

        # Get the credit card details submitted by the form
        token = self.get_argument('stripeToken')

        video_slug = self.get_argument('course_name')
        course_name = video_slug + '.mp4'
        course_length = int(self.get_argument('course_length'))
        signed_url = self.create_signed_url(course_name, course_length)
        
        price = course_length * 100
        stripe_error = ''

        if signed_url:
            # Create the charge on Stripe's servers - this will charge the user's card
            try:
                charge = stripe.Charge.create(
                    amount=price, # amount in cents, again
                    currency="usd",
                    card=token,
                    description=self.current_user.email
                )

                #save details to database
                purchase_id = self.db.execute("INSERT INTO purchases (member_id, video_slug, signed_url, date_purchased, days, price) VALUES (%s, %s, %s, UTC_TIMESTAMP(), %s, %s)", self.current_user.id, video_slug, signed_url, course_length, decimal.Decimal('9.00'))

                self.redirect('/video/' + str(purchase_id))
            except stripe.CardError, e:
                # The card has been declined
                stripe_error = 'The card has been declined'

        self.render('purchase.html', video_slug=video_slug, stripe_error=stripe_error)

    def create_signed_url(self, stream_resource, days):
        sd = self.cf.get_streaming_distribution_info('XXXXXXXXXXXXXX')

        expires = int(time.time()) + days * 86400
        signed_url = sd.create_signed_url(stream_resource, aws_key_pair_id, expires, private_key_file=aws_priv_key_file)
        
        return signed_url


class BucketHandler(BaseHandler):
    def get(self):
        s3 = boto.connect_s3()
        bucket = s3.get_bucket('videos')
        bucket_list = bucket.list()

        videos = []
        for video in bucket_list:
            videos.append(video.name)

        self.render('object.html', videos=videos)


if __name__ == "__main__":
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application(), xheaders=True)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

