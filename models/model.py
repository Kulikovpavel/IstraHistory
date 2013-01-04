from google.appengine.ext import db
from google.appengine.ext import blobstore

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
