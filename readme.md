# splicer
A TCP proxy with useful TLS and HTTP features suitable for vhosting and load balancing.

## Why
I can never get nginx to do what I want. Also wanted easy [ACME](https://github.com/ietf-wg-acme/acme/) integration, pre & post rules for HTTP (in plain JavaScript!) and websockets that work out of the box.

## How
node.js built in TCP, TLS and HTTP servers.

## Example
``` javascript
var Splicer = require('splicer')

// create a proxy
var proxy = new Splicer()

proxy.on('tcpbind', port => {
  console.log(`started listening on ${port}`)
})

proxy.on('tcpunbind', port => {
  console.log(`stopped listening on ${port}`)
})

proxy.on('connection', socket => {
  console.log(`tcp connection on ${socket.localPort} from ${socket.remoteAddress}`)
})

// map dns names to apps
proxy.names = {
  'www.secure-http.localhost': {
    appId: 'secureHTTP'
  },
  'secure-http.localhost': {
    appId: 'secureHTTP'
  },
  'secure-tcp.localhost': {
    appId: 'secureTCP'
  },
  'insecure-http.localhost': {
    appId: 'insecureHTTP'
  }
}

// configure apps
proxy.apps = {
  secureHTTP: {
    tls: true,
    http: {
      cname: 'www.secure-tcp.localhost', // forces a redirect if host header does not match
      auth: {
        username: 'password' // http basic authentication
      }
    },
    machines: {
      main: true
    },
    ports: {
      80: true, // tls option will force any unencrypted traffic that looks like http to be redirected
      443: 4430
    }
  },
  secureTCP: {
    tls: true,
    machines: {
      main: true
    },
    ports: {
      9000: 9001
    }
  },
  insecureHTTP: {
    http: {
      pre: `return req => req.headers['x-added-for-upstream'] = 'foo'`, // these get eval'd
      post: `return res => res.headers['x-added-for-client'] = 'bar'`
    },
    machines: {
      main: true
    },
    ports: {
      80: 8000
    }
  }
}

// upstream ips
// note these are not stored directly on apps to make load balancing easier
proxy.machines = {
  main: {
    address: 'localhost'
  }
}

// ACME integration
var Autocert = require('autocert')

var autocert = new Autocert({
  url: 'https://acme-staging.api.letsencrypt.org',
  email: 'info@example.com',
  challenges: proxy.challenges,
  credentials: proxy.credentials
})

proxy.SNICallback = autocert.certify.bind(autocert)

proxy.isAcmeHttpChallenge = pathname => {
  return /^\/\.well-known\/acme-challenge/.test(pathname)
}

proxy.setAcmeChallenge = autocert.setChallenge = (key, value, cb) => {
  if (value) {
    proxy.challenges[key] = value
  } else {
    delete proxy.challenges[key]
  }
  cb && cb()
}

autocert.setCredential = (name, credential, cb) => {
  proxy.credentials[name] = credential
  cb()
}

// make sure port 80 is open
proxy.apps.acme = {
  ports: {
    80: true
  }
}

// start listening
proxy.reload()
```

## License
MIT
