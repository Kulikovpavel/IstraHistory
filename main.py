#!/usr/bin/env python
# -*- coding: utf-8 -*-


import webapp2
import jinja2
import urllib
import logging
import json
import random
from time import sleep

from helpers import *

from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.ext import db
from google.appengine.api import images
from google.appengine.api import memcache


import sys # models import
sys.path.append('/models')
from models import *

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader("templates"))

# add filters for description tag
def nl2br(value):
    if hasattr(value, 'replace'):
        return value.replace('\n','<br>\n')
    else:
        return ""

jinja_environment.filters['nl2br'] = nl2br


class HistoryHandler(webapp2.RequestHandler):
    def pictures_update(self):
        sleep(0.25)  # for  changes occur, else cache missed new items or deleted ones. Street magic
        data = Picture.all().order('-created').fetch(300)
        memcache.set('pictures_all', data)

    def get(self):
        self.response.headers.add_header('content-type', 'application/json', charset='utf-8')
        upload_url = blobstore.create_upload_url('/upload')
        data = json.dumps({'url': upload_url})
        self.response.out.write(data)

    def tags_update(self, tags):
        for tag in tags:
            if tag:
                tag_in_db = Tag.all().filter('title = ', tag).get()
                if tag_in_db:
                    tag_in_db.count += 1
                    tag_in_db.put()
                else:
                    tag_in_db = Tag(title = tag, count = 1)
                    tag_in_db.put()
        tags_data = Tag.all().order('-count').fetch(30)
        memcache.set('tags_all', tags_data)

    def tags_delete(self, tags):
        for tag in tags:
            if tag:
                tag_in_db = Tag.all().filter('title = ', tag).get()
                if tag_in_db:
                    tag_in_db.count -= 1
                    if tag_in_db.count<1:# delete Tags with 0 count
                        tag_in_db.delete()
                    else:
                        tag_in_db.put()
                else:
                    logging.error("Tag not found while delete: "+tag)
        tags_data = Tag.all().order('-count').fetch(30)
        memcache.set('tags_all', tags_data)
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

        webapp2.RequestHandler.initialize(self, *a, **kw)
        self.domain_url = self.request.host_url
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        self.template_values = {
            'url': 'url',
            'url_linktext': 'url_linktext',
            'register_url': self.register_url,
            'login_url': self.login_url,
            'user': self.user,
            'ulogin_url': self.domain_url+'/ulogin'

            }
        
class UploadHandler(HistoryHandler, blobstore_handlers.BlobstoreUploadHandler ):
    def initialize(self, *a, **kw):
        blobstore_handlers.BlobstoreUploadHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
    def post(self):
        upload_files = self.get_uploads('file')  # 'file' is file upload field in the form

#        image_type = imghdr.what(upload_files[0].filename)
#        if not image_type:
#            self.redirect('/')
        title = self.request.get('title').replace('\\','')
        description = self.request.get('description').replace('\\','')
        source = self.request.get('source').replace('\\','')

        logging.debug(self.request)
        try:
            year = int(self.request.get('year'))
        except:
            year = 1945
        tags = list(self.request.get('tags').lower().replace('\\','').replace("'",'').split(','))  # теги в нижний регистр, разделяем по запятой и в лист

        coordinates = self.request.get('coordinates')
        direction = self.request.get('direction')
        if not coordinates:
            coordinates = '55.914125,36.860562' # center of Istra if no coords
        if direction:
            direction = int(direction)
        else:
            direction = 9

        if upload_files and self.user:
            blob_info = upload_files[0]
            key = blob_info.key()
#            print tags
            picture = Picture(blob_key = key ,
                link = images.get_serving_url(key, size = 0),
                thumb = images.get_serving_url(key, size = 75),
                user = self.user,
                title = title,
                description = description,
                source = source,
                year = year,
                tags = tags,
                coordinates = coordinates,
                direction = direction)
            picture.put()
            memcache.set('picture_' + str(picture.key().id()),picture)
            self.tags_update(tags)
            self.pictures_update()

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
        tag_id = self.request.get('tag')
        tag = None
        if tag_id:
            tag = Tag.get_by_id(int(tag_id))

        if tag:
            mem_string='picture_tag_'+str(tag_id)
            data = memcache.get(mem_string)
            if data is None:

                data = Picture.all().filter('tags =',tag.title)
                memcache.set(mem_string, data)
        else:
            data = memcache.get('pictures_all')
            if data is None:
                self.pictures_update()
                data = memcache.get('pictures_all')
        
        self.template_values['pictures'] = data

        tags_data = memcache.get('tags_all')
        if tags_data is None:
            tags_data = Tag.all().order('-count').fetch(30)
            memcache.set('tags_all', tags_data)

        self.template_values['tags'] = tags_data
        self.template_values['tags_list'] = [x.title for x in tags_data]
        template = jinja_environment.get_template('index.html')
        self.response.out.write(template.render(self.template_values))


class UserPage(HistoryHandler):
    def get(self):
        if self.user:
            self.template_values['pictures'] = self.user.pictures
            template = jinja_environment.get_template('userpage.html')
            self.response.out.write(template.render(self.template_values))
        else:
            self.redirect('/login')


class LoadPage(HistoryHandler):
    def get(self):
        if self.user:
            tags_data = memcache.get('tags_all')
            if tags_data is  None:
                tags_data = Tag.all().order('-count').fetch(30)
                memcache.set('tags_all', tags_data)

            self.template_values['tags_list'] = ("["+''.join(["'"+x.title+"'," for x in tags_data if x.title])+"]").replace('\\','')
#            self.template_values['tags_list'] = list(x.title for x in tags_data if x.title)
            msg = self.request.get("msg")
            template = jinja_environment.get_template('upload.html')
            self.template_values['msg'] = msg
            self.response.out.write(template.render(self.template_values))

        else:
            self.redirect('/login')

class PicturePage(HistoryHandler):
    def post(self, id):
        action = self.request.get('action')
        id = int(urllib.unquote(id))
        picture = Picture.get_by_id(id)
        if action == 'delete' and picture and picture.user.key() == self.user.key():
            self.tags_delete(picture.tags) # update Tags, -1 count or delete at all
            picture.delete()
            self.pictures_update()
        self.redirect('/userpage')

    def get(self, id):
        id = int(urllib.unquote(id))
        picture = memcache.get("picture_" + str(id))
        if not picture:
            picture = Picture.get_by_id(id)
        comments = memcache.get('comments_' + str(id))
        if not comments:
            comments = picture.comments.fetch(1000)
        if picture:
            memcache.set("picture_" + str(id), picture)
            memcache.set('comments_' + str(id), comments)
            template = jinja_environment.get_template('picture.html')
            self.template_values['picture'] = picture
            tags = memcache.get("picture_tags_"+str(id))
            if tags is None:
                tags = [Tag.all().filter('title =', x).get() for x in picture.tags]
            self.template_values['tags'] = tags
            self.template_values['comments'] = comments

            self.response.out.write(template.render(self.template_values))

        else:
            self.redirect('/')


class ULoginHandler(HistoryHandler):
    def post(self):
        # gets JSON from ULogin
        token = self.request.get('token')
        params ={'token': token, 'host': self.domain_url}
        params = urllib.urlencode(params)

        f = urllib.urlopen("http://ulogin.ru/token.php?%s" % params)
        ulogin = json.load(f)
        logging.debug(ulogin)
        if (not 'error' in ulogin) and 'email' in ulogin and ulogin['verified_email'] == '1':# email is confirmed
            email = ulogin['email']

            user = User.by_email(ulogin['email'])
            if user:  # if user is found - login with it
                self.login(user)

            else:  # else create new User
                username = ulogin['first_name'] + ' ' + ulogin['last_name']# gets "Ivan Ivanov" string for name
                chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                password = ''.join(random.choice(chars) for _ in range(10))
                u = User.register(username, email, password)
                u.put()
                self.login(u)
        else:
            logging.warning('Problems with ulogin')


        self.redirect('/')

class PicturesAPI(webapp2.RequestHandler):
    def get(self):
        data = memcache.get('pictures_all')
#        self.response.headers.add_header('content-type', 'application/json', charset='utf-8')
        data = json.dumps([[[x.coordinates[0], x.coordinates[1]], x.title, x.link, x.thumb]
                           for x in data if x.coordinates])
        self.response.out.write(data)

class CommentHandler(HistoryHandler):
    def post(self):
        owner_id = self.request.get('owner', default_value='1')
        picture_id = self.request.get('picture_id', default_value='1')
        text = self.request.get('text')


#        try:
        owner = Comment.get_by_id(int(owner_id))
#        except:
#            owner = None
#            logging.debug("no owner")

        picture = Picture.get_by_id(int(picture_id))
        if self.user and picture:
            comment = Comment(user=self.user,
                              picture=picture,
                              text=text,
                              )
            if owner:
                comment.owner = owner
            comment.put()
            memcache.set('comments_'+picture_id,picture.comments.fetch(1000))
        else:
            self.redirect('/login')

        self.redirect('/picture/'+picture_id)


class PictureEditPage(HistoryHandler):
    def get(self,id):
        id =  int(urllib.unquote(id))
        picture = memcache.get("picture_" + str(id))
        if not picture:
            picture = Picture.get_by_id(id)

        if self.user.key() <> picture.user.key():
            self.redirect('/login')

        self.template_values['picture'] = picture
        template = jinja_environment.get_template('picture_edit.html')

        tags_data = memcache.get('tags_all')
        if tags_data is  None:
            tags_data = Tag.all().order('-count').fetch(30)
            memcache.set('tags_all', tags_data)

        self.template_values['tags_list'] = ("["+''.join(["'"+x.title+"'," for x in tags_data if x.title])+"]").replace('\\','')
        self.template_values['tags'] = ("["+''.join(["'"+x+"'," for x in picture.tags])+"]").replace('\\','')
        self.response.out.write(template.render(self.template_values))

    def post(self,id):
        id = int(urllib.unquote(id))
        picture = memcache.get("picture_" + str(id))
        if not picture:
            picture = Picture.get_by_id(id)
        if self.user.key() <> picture.user.key():
            self.redirect('/login')

        title = self.request.get('title').replace('\\','')
        description = self.request.get('description').replace('\\','')
        source = self.request.get('source').replace('\\','')

        year = int(self.request.get('year'))
        tags = list(self.request.get('tags').lower().replace('\\','').replace("'",'').split(','))  # теги в нижний регистр, разделяем по запятой и в лист

        coordinates = self.request.get('coordinates')
        direction = self.request.get('direction')
        if not coordinates:
            coordinates = '55.914125,36.860562' # center of Istra if no coords
        if direction:
            direction = int(direction)
        else:
            direction = 9

        picture.title = title
        picture.description = description
        picture.source = source
        picture.year = year
        picture.tags = tags
        picture.coordinates = coordinates
        picture.direction = direction
        picture.save()
        memcache.set('picture_' + str(picture.key().id()),picture)
        self.tags_update(tags)
        self.pictures_update()

        # self.redirect(images.get_serving_url(key))
        # self.redirect('/serve/%s' %key )
        self.redirect('/picture/' + str(id))


class OldMapsHandler(HistoryHandler):
    def get(self):
        template = jinja_environment.get_template('oldmaps.html')
        self.response.out.write(template.render(self.template_values))


class ChangesHandler(HistoryHandler):
    def get(self):
        template = jinja_environment.get_template('changes.html')
        self.response.out.write(template.render(self.template_values))


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/userpage', UserPage),
    ('/load', LoadPage),
    ('/upload', UploadHandler),
    ('/serve/([^/]+)?', ServeHandler),
    ('/login', LoginHandler),
    ('/register',RegisterHandler),
    ('/logout',Logout),
    ('/picture/(\d+)', PicturePage),
    ('/picture/edit/(\d+)', PictureEditPage),
    ('/ulogin', ULoginHandler),
    ('/pictures_api', PicturesAPI),
    ('/comment', CommentHandler),
    ('/oldmaps', OldMapsHandler),
    ('/changes', ChangesHandler),
], debug=True)
