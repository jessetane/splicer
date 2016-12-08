# terminus
A TCP proxy with useful TLS and HTTP features suitable for vhosting and load balancing.

## Why
I can never get nginx to do what I want. Also wanted easy [ACME](https://github.com/ietf-wg-acme/acme/) integration, pre & post rules for HTTP (in plain JavaScript!) and websockets that just work by default.

## How
node.js' built in TCP, TLS and HTTP servers.

## Example
``` javascript
var Terminus = require('terminus')

// create a proxy
var proxy = new Terminus({
  acmeValidationPort: 80
})

proxy.isDomainValidationRequest = pathname => {
  return /^\/\.well-known\/acme-challenge/.test(pathname)
}

proxy.on('tcpbind', port => {
  console.log(`started listening on ${port}`)
})

proxy.on('tcpunbind', port => {
  console.log(`stopped listening on ${port}`)
})

proxy.on('connection', socket => {
  console.log(`tcp connection on ${socket.localPort} from ${socket.remoteAddress}`)
})

// tell the proxy about dns names, upstream apps and machines
proxy.names = {
  'www.secure-tcp.localhost': {
    appId: 'secureHTTP'
  },
  'secure-tcp.localhost': {
    appId: 'secureHTTP'
  },
  'secure-http.localhost': {
    appId: 'HTTP'
  },
  'insecure-http.localhost': {
    appId: 'insecureHTTP'
  }
}

proxy.apps = {
  secureHTTP: {
    tls: true,
    http: {
      cname: 'www.secure-tcp.localhost' // forces a redirect if host header does not match
    },
    machines: {
      main: true
    },
    ports: {
      80: true, // tls option will force any unencrypted http traffic to be redirected but we may still want to listen here
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
      pre: `return req => req.headers['x-added-for-upstream'] = 'foo'`, // these get eval'ed via new Function
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

proxy.machines = {
  main: {
    address: 'localhost'
  }
}

// ACME CA integration
var Autocert = require('autocert')

var autocert = new Autocert({
  url: 'https://acme-staging.api.letsencrypt.org',
  email: 'info@example.com',
  challenges: proxy.challenges,
  credentials: proxy.credentials
})

autocert.setChallenge = (key, value, cb) => {
  proxy.challenges[key] = value
  cb()
}

autocert.setCredential = (name, credential, cb) => {
  proxy.credentials[name] = credential
  cb()
}

proxy.challenges = {}
proxy.credentials = {}
proxy.SNICallback = autocert.certify.bind(autocert)
proxy.setChallenge = autocert.setChallenge

// reload and start serving
proxy.reload()
```

## License
MIT
