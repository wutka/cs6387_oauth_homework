# CS 6387 Homework - OAUTH2 Authorization Grant

This is a short example of an OAUTH2 authorization grant request.
It consists of two web servers, one representing the web application
that the browser interacts with, the other representing a resource server
that the web application interacts with, and which verifies the user's
authorization token that is passed from the web server.

## Build
To build the servers, use the following two commands:
```
go build -o ws web_server/main.go
go build -o rs resource_server/main.go
```

## Run
In separate windows, run the ws and rs commands. The ws command creates
a web server that listens on port 8000, while rs creates one that listens
on port 9000:
```
./ws
```

```
./rs
```

Then, point your browser at http://localhost:8000/
![Browser pointed at http://localhost:8000/](https://raw.githubusercontent.com/wutka/cs6387_oauth_homework/master/images/browser1.png)


You should now see an OKTA login page, like this:
![OKTA login page](https://raw.githubusercontent.com/wutka/cs6387_oauth_homework/master/images/okta.png)

Enter the login credentials, and you should see a plain web page
showing the user number that was allocated for your session, assuming
that the authorization token was accepted by the resource server:
![User number shown](https://raw.githubusercontent.com/wutka/cs6387_oauth_homework/master/images/browser.png)

Both servers print out some interim log messages to show the interaction
with the Okta OAUTH2 server. This is the output from ws (the web server):
![Output from ws server](https://raw.githubusercontent.com/wutka/cs6387_oauth_homework/master/images/ws.png)

This is the output from ws (the resource server):
![Output from rs server](https://raw.githubusercontent.com/wutka/cs6387_oauth_homework/master/images/rs.png)
