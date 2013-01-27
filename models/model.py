from google.appengine.ext import db
from google.appengine.ext import blobstore
from google.appengine.api import images


from helpers import *

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
    description = db.StringProperty(multiline=True)
    source = db.StringProperty()
    blob_key = blobstore.BlobReferenceProperty(blobstore.BlobKey, required=True)
    link = db.StringProperty()
    thumb = db.StringProperty()
    user = db.ReferenceProperty(User,required = True,  collection_name='pictures')
    tags = db.StringListProperty()
    year = db.IntegerProperty()
    date = db.DateTimeProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    coordinates = db.GeoPtProperty()
    direction = db.IntegerProperty()


    def link_func(cls,key):
        return images.get_serving_url(key, size = 0)

    def thumb_func(cls,key):
        return images.get_serving_url(key, size = 75)

class Tag(db.Model):
    title = db.StringProperty()
    count = db.IntegerProperty()
