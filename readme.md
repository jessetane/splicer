# splicer
A TCP proxy with useful TLS and HTTP features suitable for virtual hosting and load balancing.

## Why
Because [nginx is weird](https://www.nginx.com/resources/wiki/start/topics/depth/ifisevil/). I also wanted easy [ACME](https://github.com/ietf-wg-acme/acme/) integration, pre & post hooks for HTTP stuff (in plain JavaScript!) and websockets that Just Work.

## How
node.js built in TCP, TLS and HTTP servers.

## Example

### Batteries included executable:
Install:
```shell
npm i -g splicer
```

Create a config file:
```shell
cat << EOF > ./config.json
{
  "names": {
    "my.domain.com": "demo"
  },
  "apps": {
    "demo": {
      "ports": {
        "80": "8000",
        "443": "8000"
      },
      "machines": {
        "localhost": true
      },
      "root": "/var/www/my.domain.com/public",
      "tls": true
    }
  },
  "machines": {
    "localhost": {
      "address": "127.0.0.1"
    }
  },
  "fileServerPort": "8000"
}
EOF
```
Note that this file will be modified at run time to store certificates and signing keys.

Start the proxy:
```shell
splicer config.json
```

Dynamic config reload:
```shell
kill -s HUP "$(pgrep -fn splicer)"
```

### As a JavaScript module
See also example/index.js
```javascript
import Splicer from 'splicer'

// create a proxy
const proxy = new Splicer()

proxy.on('tcpbind', port => {
  console.log(`started listening on ${port}`)
})

proxy.on('tcpunbind', port => {
  console.log(`stopped listening on ${port}`)
})

proxy.on('connection', socket => {
  console.log(`tcp connection on ${socket.localPort} from ${socket.remoteAddress}`)
})

proxy.on('request', (socket, name, app) => {
  console.log(`[${new Date().toISOString()}] request for ${name} on ${socket.localPort} from ${socket.remoteAddress}`)
})

// map dns names to apps
proxy.names = {
  'www.secure-http.localhost': 'secureHTTP',
  'secure-http.localhost': 'secureHTTP',
  'secure-tcp.localhost': 'secureTCP',
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
      80: true, // mapping 80 to a specific destination port is unnecessary for apps that set the tls option
                // but it should be explitly opened for answering acme http challenges and redirecting new visitors
      443: 4430
    }
  },
  secureTCP: {
    tls: {
      front: true,
      back: false // tls option can be an object to indicate if backend connections should use tls
    },
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

// you can optionally override `balanceLoad`, by default it returns the first known machine
proxy.balanceLoad = app => {
  const firstMachine = Object.keys(app.machines)[0]
  return proxy.machines[firstMachine]
}

// ACME integration
const Autocert = require('autocert')

const autocert = new Autocert({
  url: 'https://acme-staging-v02.api.letsencrypt.org/directory',
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

// start listening
proxy.reload()
```

## License
MIT
