# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re
import hmac
import webapp2
import jinja2

from dbmodels import User, Post, Comment
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# User Helper Functions for Cookie management

secret = "asdhwng.snpvwor^"


def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split("|")[0]
    if make_secure_val(val) == secure_val:
        return val


# Handler classes

# Base class for all other handler classes
class BlogHandler(webapp2.RequestHandler):
    """docstring for BlogHandler"""
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        print params
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
                'Set-Cookie',
                '%s=%s' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def userLoggedIn(self):
        if self.user:
            return True

    def isPostOwner(self, post):
        if self.user.key().id() == post.user_id:
            return True


# URL HANDLERS

# Main Blog Page
class MainPage(BlogHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/html'
        query = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        self.render("index.html", posts=query.fetch(None),
                    loggedIn=self.userLoggedIn(),
                    user=self.user)


# Invidual page for each Post
# Also handles POST requests for Comment posting and Likes
class BlogPage(BlogHandler):
    def get(self, post_id, error=None, errorComment=None):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        comments = Comment.all().filter("post =", post).order("created")
        likes = len(post.likes)

        privatepage = self.userLoggedIn() and self.isPostOwner(post)
        print "Debug:  ", self.userLoggedIn(), self.user, error
        self.render("permalink.html", post=post,
                    privatepage=privatepage,
                    loggedIn=self.userLoggedIn(),
                    user=self.user,
                    comments=comments,
                    likes=likes,
                    error=error,
                    errorComment=errorComment)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if self.userLoggedIn():
            error = None
            errorComment = None
            action = self.request.get("action")

            if action == "comment":
                commentText = self.request.get("comment")

                if commentText:
                    comment = Comment(comment=commentText,
                                      post=post,
                                      user=self.user,
                                      parent=post)
                    comment.put()
                else:
                    errorComment = "Please make sure comment field is filled"

            elif action == "like":
                if self.isPostOwner(post):
                    error = "You cannot like your own post"
                else:
                    if self.user.key() not in post.likes:
                        post.likes.append(self.user.key())
                        post.put()
                    else:
                        post.likes.remove(self.user.key())
                        post.put()
                        error = "You already clicked earlier. Unliking it."

            self.get(post_id, error=error, errorComment=errorComment)

        else:
            self.redirect('/error')


# Create Post Page
class PostHandler(BlogHandler):
    """docstring for PostHandler"""
    def get(self):
        if self.userLoggedIn():
            self.render("input.html",
                        loggedIn=self.userLoggedIn(),
                        user=self.user)
        else:
            self.redirect("/login")

    def post(self):
        if self.userLoggedIn():
            subject = self.request.get("subject")
            content = self.request.get("content")

            if subject and content:
                post = Post(subject=subject,
                            content=content,
                            user_id=self.user.key().id())
                post.put()
                self.redirect('/%s' % str(post.key().id()))
                # self.write("thanks!")
            else:
                # TODO: pass back both subject and content as well
                self.render("input.html",
                            error="Please ensure both Subject "
                                  "and Content are entered",
                            loggedIn=self.userLoggedIn(),
                            user=self.user)
        else:
            self.redirect("/login")


# Edit Post Page
class Edit(BlogHandler):
    """docstring for PostHandler"""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if self.userLoggedIn() and self.isPostOwner(post):
            self.render("edit.html",
                        post=post,
                        loggedIn=self.userLoggedIn(),
                        user=self.user)
        else:
            self.redirect("/error")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if self.userLoggedIn() and self.isPostOwner(post):
            subject = self.request.get("subject")
            content = self.request.get("content")

            if subject and content:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/%s' % str(post.key().id()))
            else:
                self.render("edit.html",
                            error="Please ensure both Subject "
                                  "and Content are entered",
                            subject=subject,
                            content=content,
                            loggedIn=self.userLoggedIn(),
                            user=self.user)
        else:
            self.redirect("/error")


# Delete Post
class Delete(BlogHandler):
    """docstring for PostHandler"""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if self.userLoggedIn() and self.isPostOwner(post):
            self.render("delete.html",
                        post=post,
                        loggedIn=self.userLoggedIn(),
                        user=self.user)
        else:
            self.redirect("/error")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if self.userLoggedIn() and self.isPostOwner(post):
            post.delete()
            self.redirect('/')
        else:
            self.redirect("/error")


class CommentEdit(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id),
                               'Comment', int(comment_id))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return

        if self.userLoggedIn() and comment.user.key() == self.user.key():
            self.render("comment_edit.html",
                        comment=comment,
                        loggedIn=self.userLoggedIn(),
                        user=self.user)
        else:
            self.redirect("/error")

    def post(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id),
                               'Comment', int(comment_id))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return

        if self.userLoggedIn() and comment.user.key() == self.user.key():
            commentText = self.request.get("comment")
            if commentText:
                comment.comment = commentText
                comment.put()
                self.redirect('/' + str(comment.post.key().id()))
            else:
                self.render("comment_edit.html",
                            comment=comment,
                            error="Please ensure that comment field is filled",
                            loggedIn=self.userLoggedIn(),
                            user=self.user)
        else:
            self.redirect("/error")


class CommentDelete(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id),
                               'Comment', int(comment_id))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return

        if self.userLoggedIn() and comment.user.key() == self.user.key():
            self.render("comment_delete.html",
                        comment=comment,
                        loggedIn=self.userLoggedIn(),
                        user=self.user)
        else:
            self.redirect("/error")

    def post(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id),
                               'Comment', int(comment_id))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return

        if self.userLoggedIn() and comment.user.key() == self.user.key():
            post_id = comment.post.key().id()
            comment.delete()
            self.redirect('/' + str(post_id))
        else:
            self.redirect("/error")


# Display Login Error
class Error(BlogHandler):
    def get(self):
        self.render("error.html",
                    loggedIn=self.userLoggedIn(),
                    user=self.user)


# User Helper Functions

# Check username validity
USER_RE = re.compile("^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


# Check password validity
PASS_RE = re.compile("^.{3,20}$")


def valid_password(password):
    return password and USER_RE.match(password)


# Check email validity
EMAIL_RE = re.compile("^[\S]+@[\S]+.[\S]+$")


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Sign-up page base class
class Signup(BlogHandler):
    def get(self):
        self.render("signup.html",
                    loggedIn=self.userLoggedIn(),
                    user=self.user)

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        print self.username
        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username"
            have_error = True
        elif User.by_name(self.username):
            params['error_username'] = "That username is not available"
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That's not a valid password"
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords do not match"
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email"
            have_error = True

        if have_error:
            print params
            self.render("signup.html",
                        loggedIn=self.userLoggedIn(),
                        user=self.user,
                        **params)
        else:
            self.done()


# Sign-up page
class Register(Signup):
    def done(self):
        # make sure user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html',
                        error_username=msg,
                        loggedIn=self.userLoggedIn(),
                        user=self.user)
        else:
            u = User.register(self.username,
                              self.password,
                              self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


# Login page
class Login(BlogHandler):
    def get(self):
        self.render('login.html',
                    loggedIn=self.userLoggedIn(),
                    user=self.user)

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = "Invalid login"
            self.render('login.html',
                        error=msg,
                        loggedIn=self.userLoggedIn(),
                        user=self.user)


# Logout url handler
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


# Welcome page
class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render("welcome.html",
                        username=self.user.name,
                        loggedIn=self.userLoggedIn(),
                        user=self.user)
        else:
            self.redirect('/signup')


# URL Routing
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newpost', PostHandler),
    ('/([0-9]+)', BlogPage),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/welcome', Welcome),
    ('/([0-9]+)/edit', Edit),
    ('/([0-9]+)/delete', Delete),
    ('/([0-9]+)/([0-9]+)/edit', CommentEdit),
    ('/([0-9]+)/([0-9]+)/delete', CommentDelete),
    ('/error', Error),
], debug=False)
