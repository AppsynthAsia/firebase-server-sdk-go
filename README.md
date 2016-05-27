Firebase Server SDK for Golang
==============================

This is the Firebase Server SDK written in Golang.

Note that this is not an official SDK written by Google/Firebase.  Firebase only
offers the Server SDK in [Java][1] and [Node.js][2].  This is simply an attempt to
implement the Firebase Server SDK by reverse engineering the official ones.

This SDK, like its Java and Node counterparts, supports the following functions
needed on the application server:

- Authentication
  * Create custom tokens suitable for integrating custom auth systems with
    Firebase apps.
  * Verify ID tokens, which are used to pass the signed-in user from a client app
    to a backend server.
- Realtime Database (Not implemented yet)
  * Save data.
  * Retrieve data.

Initialize Firebase
-------------------

Once you have created a [Firebase console][3] project and downloaded a JSON file
with your service account credentials, you can initialize the SDK with this
code snippet:

    firebase.InitializeApp(&firebase.Options{
    	DatabaseURL: "http://databaseName.firebaseio.com",
    	ServiceAccountPath: "path/to/serviceAccountCredentials.json",
    })

You can find your database name on the Database page of your Firebase console
project.

Create Custom Tokens
--------------------

To create a custom token, pass the unique user ID used by your auth system to
the CreateCustomToken() method:

    auth, _ := firebase.GetAuth()
    token, err := auth.CreateCustomToken(userId, nil)

You can also optionally specify additional claims to be included in the custom
token.  These claims will be available in the `auth/request.auth` objects in
your Security Rules.  For example:

    auth, _ := firebase.GetAuth()
	developerClaims = make(firebase.Claims)
	developerClaims["premium_account"] = true
    token, err := auth.CreateCustomToken(userId, &developerClaims)

Verify ID Tokens
----------------

To verify and decode an ID Token with the SDK, pass the ID Token to the
VerifyIDToken method.  If the ID Token is not expired and is properly signed,
the method decodes the ID Token.

    auth, _ := firebase.GetAuth()
    decodedToken, err := auth.VerifyIDToken(idTokenString)
    if err == nil {
    	uid, found := decodedToken.Uid()
    }

To-Do List
----------

- [ ] implement support for Realtime Database access
- [ ] add sample
- [ ] support for godoc 

Developed By
------------

* David Wu - <david@wu-man.com> - [http://blog.wu-man.com](http://blog.wu-man.com)

LICENSE
-------

    Copyright 2016 David Wu

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

[1]: https://firebase.google.com/docs/reference/serverreference/packages
[2]: https://firebase.google.com/docs/reference/node/
[3]: https://firebase.google.com/console/ 