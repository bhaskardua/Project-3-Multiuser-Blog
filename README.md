# Multiuser Blog

## Public URL

You can access the website deployed on the Google App Engine here:

- https://multiuser-blog-151921.appspot.com

## Source Code

Source code can be obtained from the Github repo [here](https://github.com/bhaskardua/Project-3-Multiuser-Blog.git)

## Local Installation and Cloud Deployment

- [Install Python](https://www.python.org/downloads/) if necessary.
- [Install Google App Engine SDK](https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python).
- [Sign Up for a Google App Engine Account](https://console.cloud.google.com/appengine/).
- Create a new project in [Google’s Developer Console](https://console.cloud.google.com/) using a unique name.
- Follow the [App Engine Quickstart](https://cloud.google.com/appengine/docs/python/quickstart) to get a sample app up and running.
- Deploy the downloaded project with `gcloud app deploy`.
    - View your project at unique-name.appspot.com.
    - You should see the Multiuser Blog similar to the one deployed on the URL above. Unlike the above URL it would be mostly blank without any dummy posts and comments. 
- When developing locally, you can use `dev_appserver.py` to run a copy of your app on your own computer, and access it at [http://localhost:8080/](http://localhost:8080/).
