#!/usr/bin/env python
# -*- coding: utf-8 -*-

import webapp2
import jinja2
import os
import urllib
import hashlib
import hmac
import random
import logging
from string import letters

from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.ext import db
from google.appengine.api import images
from google.appengine.api import memcache
from google.appengine.api import users

jinja_environment = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)))

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
    
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    @classmethod
    def by_email(cls, email):
        u = User.all().filter('email =', email).get()
        return u
    @classmethod
    def register(cls, name, email, pw ):
        pw_hash = make_pw_hash(email, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, email, pw):
        u = cls.by_email(email)
        if u and valid_pw(email, pw, u.pw_hash):
            return u

class Picture(db.Model):
    title = db.StringProperty()
    blob_key = blobstore.BlobReferenceProperty(blobstore.BlobKey, required=True)
    link = db.StringProperty()
    thumb = db.StringProperty()
    user = db.ReferenceProperty(User,required = True,  collection_name='pictures')
    tags = db.StringListProperty()
    year = db.IntegerProperty()
    date = db.DateTimeProperty()
    created = db.DateTimeProperty(auto_now_add=True)

class Tag(db.Model):
    count = db.IntegerProperty()


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(email, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(email + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(email, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(email, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)
### cookies
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class HistoryHandler(webapp2.RequestHandler):
    def tags_update(self, tags):
        tags_data = memcache.get('tags_all')
        if tags_data is  None:
            tags_data = Tag.all()
            memcache.add('tags_all', tags_data, 60)

        for tag in tags:
            key = db.Key.from_path('Tag', tag)
            tag_in_db = db.get(key)
            if tag_in_db:
                tag_in_db.count += 1
                tag_in_db.put()
            else:
                tag_in_db = Tag(key_name = tag, count = 1)
                tag_in_db.put()
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        self.register_url = '/register'
        self.login_url = '/login'
        self.logout_url = '/logout'
        self.upload_url = blobstore.create_upload_url('/upload')
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        if self.user:
            self.greeting = (u"<p>Добро пожаловать, <a href='userpage'>%s</a>! <a href=\"%s\">выйти</a>)</p>" %
                        (self.user.name, self.logout_url))

        else:
            self.greeting = (u"<a href=\"%s\">Войдите или зарегистрируйтесь</a>" %
                        self.login_url)
        self.template_values = {
            'greeting': self.greeting,
            'url': 'url',
            'url_linktext': 'url_linktext',
            'upload_url': self.upload_url,
            'register_url': self.register_url,
            'login_url': self.login_url,
            'user': self.user,
            }
        
class UploadHandler(blobstore_handlers.BlobstoreUploadHandler, HistoryHandler):
    def initialize(self, *a, **kw):
        blobstore_handlers.BlobstoreUploadHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
    def post(self):
        upload_files = self.get_uploads('file')  # 'file' is file upload field in the form
        title = self.request.get('title')
        year = int(self.request.get('year'))
        tags = list(self.request.get('tags').lower().split(','))  # теги в нижний регистр, разделяем по запятой и в лист
        if upload_files and self.user:
            
            blob_info = upload_files[0]
            key = blob_info.key()
            picture = Picture(blob_key = key , 
                              link = images.get_serving_url(key),
                              thumb = images.get_serving_url(key, size=75),
                              user = self.user,
                              title = title,
                              year = year,
                              tags = tags,)
            picture.put()

            self.tags_update(tags)


            # self.redirect(images.get_serving_url(key))
            # self.redirect('/serve/%s' %key )
            self.redirect('/')
        else:
            self.redirect('/')

class ServeHandler(blobstore_handlers.BlobstoreDownloadHandler):
    def get(self, resource):
        resource = str(urllib.unquote(resource))
        blob_info = blobstore.BlobInfo.get(resource)
        self.send_blob(blob_info) 




class LoginHandler(HistoryHandler):
    def get(self):
        msg = self.request.get("msg")
        template = jinja_environment.get_template('login.html')
        self.template_values['msg'] = msg
        self.response.out.write(template.render(self.template_values))

    def post(self):
        self.password = self.request.get('password')
        self.email = self.request.get('email')
       

        u = User.login(self.email, self.password)
        if u:
            self.login(u)
            # main_user = self.user
            self.redirect('/userpage')
        else:
            msg = 'Invalid login or password'
            self.redirect('/login?msg='+msg)

class RegisterHandler(HistoryHandler):
    def get(self):
        pass
    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.email = self.request.get('email')

        if self.email:
            u = User.by_email(self.email)
        if u:
            msg = 'That user already exists.'
            self.redirect('/register?error='+ msg)
        else:
            u = User.register(self.username, self.email, self.password)
            u.put()

            self.login(u)
            self.redirect('/')

class Logout(HistoryHandler):
    def get(self):
        self.logout()
        self.redirect('/')

class MainPage(HistoryHandler):
    def get(self):
        data = memcache.get('pictures_all')
        if data is  None:
            data = Picture.all()
            memcache.add('pictures_all', data, 60)
        
        
        self.template_values['pictures'] = data
        print self.template_values
        template = jinja_environment.get_template('index.html')
        self.response.out.write(template.render(self.template_values))
    
class UserPage(HistoryHandler):
    def get(self):
        if self.user:
            template_values = {
                'pictures': self.user.pictures,
            
            }
            template = jinja_environment.get_template('userpage.html')
            self.response.out.write(template.render(template_values))
        else:
            self.redirect('/login')
        
class LoadPage(HistoryHandler):
    def get(self):
        if self.user:
            msg = self.request.get("msg")
            template = jinja_environment.get_template('upload.html')
            self.template_values['msg'] = msg
            self.response.out.write(template.render(self.template_values))

        else:
            self.redirect('/login')

secret = 'far654654dsfsfdt'


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/userpage', UserPage),
    ('/load', LoadPage),
    ('/upload', UploadHandler),
    ('/serve/([^/]+)?', ServeHandler),
    ('/login', LoginHandler),
    ('/register',RegisterHandler),
    ('/logout',Logout),
], debug=True)
