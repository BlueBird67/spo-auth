var https = require('https'),
    http = require('http'),
    xml2js = require('xml2js'),
    cookie = require('cookie');

var defaults = {
    contextInfo : '/_api/contextinfo',
    wsignin : '/_forms/default.aspx?wa=wsignin1.0',
    stsHost : 'login.microsoftonline.com',
    stsPath : '/extSTS.srf'
};

var samlRequestTemplate = '' +
'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
  '<s:Header>' +
    '<a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>' +
    '<a:ReplyTo>' +
      '<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>' +
    '</a:ReplyTo>' +
    '<a:To s:mustUnderstand="1">https://login.microsoftonline.com/extSTS.srf</a:To>' +
    '<o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
      '<o:UsernameToken>' +
        '<o:Username>[username]</o:Username>' +
        '<o:Password>[password]</o:Password>' +
      '</o:UsernameToken>' +
    '</o:Security>' +
  '</s:Header>' +
  '<s:Body>' +
    '<t:RequestSecurityToken xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">' +
      '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">' +
        '<a:EndpointReference>' +
          '<a:Address>[endpoint]</a:Address>' +
        '</a:EndpointReference>' +
      '</wsp:AppliesTo>' +
      '<t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>' +
      '<t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>' +
      '<t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>' +
    '</t:RequestSecurityToken>' +
  '</s:Body>' +
'</s:Envelope>';

function verify(options){
    if(!options.login || !options.password || !options.host) {
        throw new Error('You have to specify login, password and host');
    }

    var opts = {
        login : options.login,
        password : options.password,
        host : options.host,
        stsHost: options.stsHost || defaults.stsHost,
        stsPath: options.stsPath || defaults.stsPath,
        wsignin: options.wsignin || defaults.wsignin
    };

    return opts;
}

function parseSecurityToken(data, callback){
    var parser = new xml2js.Parser({ emptyTag: '' });
    parser.on('end', function (js) {
      if (js['S:Envelope']['S:Body'][0]['S:Fault']) {
            var error = js['S:Envelope']['S:Body'][0]['S:Fault'][0]['S:Detail'][0]['psf:error'][0]['psf:internalerror'][0]['psf:text'];
            callback(error, null);
            return;
        }
        var token = js['S:Envelope']['S:Body'][0]['wst:RequestSecurityTokenResponse'][0]['wst:RequestedSecurityToken'][0]['wsse:BinarySecurityToken'][0]['_'];
        callback && callback(null, token)
    });

    parser.parseString(data);
}

function getSamlRequest(options, callback){
    var samlRequest = samlRequestTemplate
        .replace('[username]', options.login)
        .replace('[password]', options.password)
        .replace('[endpoint]', options.host);

    var opts = {
        method: 'POST',
        host: options.stsHost,
        path: options.stsPath,
        body: samlRequest,
        headers: {
            'Content-Length': samlRequest.length
        }
    };

    var req = https.request(opts, function (res) {
        var xml = '';
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            xml += chunk;
        })

        res.on('end', function () {
            callback && callback(null, xml);
        });
    });

    req.on('error', function(e) {
        callback && callback(e, null);
    });

    req.end(samlRequest);

    return req;
}

function getFedRequest(options, callback) {
    var opts = {
        method: 'POST',
        host: options.host,
        path: options.wsignin,
        headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)'
        }
    };

    var req = https.request(opts, function (res) {
        var xml = '';

        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            xml += chunk;
        });

        res.on('end', function () {
            var setCookieHeaders = res.headers["set-cookie"];

            var cookies = {};
            if(setCookieHeaders) {
                setCookieHeaders.forEach(function (str) {
                    var parsedCookie = cookie.parse(str);
                    if(parsedCookie.FedAuth) {
                        cookies.FedAuth = parsedCookie.FedAuth;
                    }

                    if(parsedCookie.rtFa) {
                        cookies.rtFa = parsedCookie.rtFa;
                    }
                });
            }
            cookies.rtFa && cookies.FedAuth && callback && callback(null, cookies)
        });

        res.on('error', function (err, data) {
            callback && callback(err, null);
        });
    });

    req.end(options.securityToken);
}

function getDigestRequest(options, callback){
    var opts = {
        method: "POST",
        host: options.host,
        path: "/_api/contextinfo",
        headers: {
            'Accept': 'application/json',
            'Content-type': 'application/json',
            'Cookie': 'FedAuth=' + options.FedAuth + '; rtFa=' + options.rtFa,
            'Content-length': 0
        }
    };

    var req = https.request(opts, function (res) {
        var content = '';

        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            content += chunk;
        });

        res.on('error', function (err) {
            callback && callback(err, null);
        });

        res.on('end', function () {
            var digest = JSON.parse(content);
            if(digest && digest.FormDigestValue && callback) {
                callback(null, digest.FormDigestValue);
            }
        });
    })

    req.end('');
}

function getAccessToken(options, callback){
    var opts = verify(options);

    getSamlRequest(opts, function (err, data) {
        if(err) {
            callback && callback(err, null);
            return;
        }

        parseSecurityToken(data, function (err, data) {
            if(err) {
                callback && callback(err, null);
                return;
            }
            opts.securityToken = data;
            callback && callback(null, opts);
        });
    });
}

function getFedCookies(options, callback) {
    var opts = verify(options);

    getAccessToken(opts, function (err, data){
        if(err) {
            callback && callback(err, null);
            return;
        }

        opts.securityToken = data.securityToken;
        getFedRequest(opts, function (err, data) {
            if(err) {
                callback && callback(err, null);
                return;
            }

            opts.FedAuth = data.FedAuth;
            opts.rtFa = data.rtFa;
            callback && callback(null, opts);
        })
    });
}

function getRequestDigest(options, callback) {
    var opts = verify(options);
    getFedCookies(opts, function (err, data){
        if(err) {
            callback && callback(err, null);
            return;
        }

        opts.FedAuth = data.FedAuth;
        opts.rtFa = data.rtFa;
        getDigestRequest(opts, function (err, data) {
            if(err) {
                callback && callback(err, null);
                return;
            }

            opts.digest = data;
            callback && callback(null, opts);
        })
    });
}

module.exports = {
    getAccessToken: getAccessToken,
    getFedCookies : getFedCookies,
    getRequestDigest: getRequestDigest
}
