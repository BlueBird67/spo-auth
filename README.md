# spo-auth

#### Motivation

There are lots of good libs for the app-authentication, and [ADAL.js](https://github.com/AzureAD/azure-activedirectory-library-for-js) is awesome. But I wanted to use 'login/password' approach to make things simple for those who work on small customizations. After searching for awhile I didn't find a good module that can cover my needs. I found a few old abandoned implementations of client API interfaces to SharePoint REST services, but most of them were broken. Microsoft is constantly changing an authentication piece of Office365, so most of those libs are obsolete now. Unfortunately they are still listed on NPM. That's why I decided to roll out a new NPM module to make my life easier.

I used an awesome article about [SharePoint Online remote authentication (and Doc upload)](http://paulryan.com.au/2014/spo-remote-authentication-rest/) from Paul Ryan. It has everything you need to build an auth module for SPO in any language.

#### Install

    npm i --save spo-auth 

#### Usage

There are only 3 methods in this small lib, it is very easy to check how they work by executing this small snippet:

    var spAuth = require('spo-auth');

    var config = {
        host : "devserver.sharepoint.com",
        login : "LOGIN@devserver.onmicrosoft.com",
        password : "PASSWORD"
    };

    spAuth.getAccessToken(config, function (err, data) {
        console.log(data);
    });

    spAuth.getFedCookies(config, function (err, data) {
        console.log(data);
    });

    spAuth.getRequestDigest(config, function (err, data) {
        console.log(data);
    });

These methods are very straightforward:

* `getAccessToken` makes a request to //login.microsoftonline.com/extSTS.srf to get a security token
* `getFedCookies` calls `getAccessToken` and then makes a request to //yourdomain.sharepoint.com/_forms/default.aspx?wa=wsignin1.0 to get FedAuth and rtFa cookies
* `getRequestDigest` calls `getFedCookies` and then makes a request to //yourdomain.sharepoint.com/_api/contextinfo to get FormDigestValue

After that you will be able to use SPO REST interfaces from your code, just pass a correct header or cookie with your request.

#### Examples

Get information about a root web:

    var spAuth = require("spo-auth"),
        https = require('https');

    var config = {
        host : "devserver.sharepoint.com",
        login : "LOGIN@devserver.onmicrosoft.com",
        password : "PASSWORD"
    };

    spAuth.getRequestDigest(config, function (err, data) {
        console.log(data);
        
        var requestOptions = {            
            host: data.host,
            path: '/_api/web',
            headers: {
                'Accept': 'application/json;odata=verbose',
                'Content-type': 'application/json;odata=verbose',
                'Cookie': 'FedAuth=' + data.FedAuth + '; rtFa=' + data.rtFa,
                'X-RequestDigest': data.digest
            }
        };
        
        var req = https.request(requestOptions, function (res) {
            var resp = '';

            res.setEncoding('utf8');
            res.on('data', function (chunk) {
                resp += chunk;
            });

            res.on('error', function (err) {
                console.log(err);
            })

            res.on('end', function () {
                console.log(JSON.parse(resp));
            });
        })

        req.end('');
    });