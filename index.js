var EventEmitter = require('events')
var net = require('net')
var tls = require('tls')
var http = require('http')
var https = require('https')
var url = require('url')
var diff = require('object-diff')
var isTls = require('is-tls-client-hello')
var extractSni = require('sni')
var isHttp = /^[^ ]+ [^ ]+ HTTP\/1\.1$/m
var extractHostHeader = /\r\nhost: (.+?)(?:\r|$)/i

module.exports = class Terminus extends EventEmitter {
  constructor (opts = {}) {
    super()

    // how did es6 classes not get syntax for this?
    var toBind = [
      'onappchange',
      '_ontcpConnection',
      '_ontlsConnectionSecure',
      '_onhttpRequest'
    ]
    toBind.forEach(m => {
      this[m] = this[m].bind(this)
    })

    // public state
    this.apps = {}
    this.names = {}
    this.credentials = {}
    this.challenges = {}
    this.machines = {}

    // timeout inactive connections after 1m
    this.timeout = opts.timeout !== undefined ? opts.timeout : 60000

    // outward facing tcp listeners
    this._tcpListeners = {}

    // tcp listener for handling domain validation requests from ACME CAs
    this.acmeValidationPort = opts.acmeValidationPort
    if (this.acmeValidationPort) {
      this._tcpListeners[this.acmeValidationPort] = this._createTcpListener(this.acmeValidationPort)
    }

    // tls terminator
    this._tlsServer = new tls.Server({
      SNICallback: (name, cb) => this.SNICallback(name, cb)
    })
    this._tlsServer.on('secureConnection', this._ontlsConnectionSecure)

    // http server
    this._httpServer = new http.Server()
    this._httpServer.on('request', this._onhttpRequest)
    this._httpAgent = new http.Agent({
      keepAlive: true,
      keepAliveMsecs: this.timeout
    })
  }

  close () {
    this._httpServer.close()
    this._tlsServer.close()
    for (var port in this._tcpListeners) {
      this._tcpListeners[port].close()
    }
  }

  reload () {
    for (var id in this.apps) {
      this.onappchange({ oldData: this.apps[id] })
    }
    for (id in this.apps) {
      this.onappchange({ newData: this.apps[id] })
    }
  }

  onappchange (evt) {
    // evt object must include { newData, oldData }
    var oldData = evt.oldData || {}
    var newData = evt.newData || {}
    var oldPorts = diff(newData.ports || {}, oldData.ports || {})
    var newPorts = diff(oldData.ports || {}, newData.ports || {})
    for (var port in oldPorts) {
      var listener = this._tcpListeners[port]
      if (listener && --listener.apps === 0) {
        delete this._tcpListeners[port]
        listener.close()
        this.emit('tcpunbind', port)
      }
    }
    for (port in newPorts) {
      listener = this._tcpListeners[port]
      if (listener) {
        listener.apps++
      } else {
        this._tcpListeners[port] = this._createTcpListener(port)
      }
    }
  }

  SNICallback (name, cb) {
    var credential = this.credentials[name]
    if (credential) {
      if (!credential.context) {
        credential.context = tls.createSecureContext({
          key: credential.key,
          cert: credential.cert
        })
      }
      cb(null, credential.context)
    } else {
      cb(new Error('not found'))
    }
  }

  isDomainValidationRequest (pathname) {
    return false
  }

  setChallenge (key, value) {
    return false
  }

  balanceLoad (app) {
    return this.machines[Object.keys(app.machines)[0]]
  }

  _createTcpListener (port) {
    var listener = new net.Server()
    listener.apps = 1
    listener.on('connection', this._ontcpConnection)
    listener.listen(port, '::', err => {
      if (err) throw err
      this.emit('tcpbind', port)
    })
    return listener
  }

  _ontcpConnection (socket) {
    this.emit('connection', socket)
    socket.setTimeout(this.timeout, () => {
      console.log('TIMEOUT')
      socket.destroy()
    })
    socket.once('readable', () => {
      var firstPacket = socket.read() || new Buffer(0)
      if (isTls(firstPacket)) {
        this._ontlsConnection(socket, firstPacket)
      } else {
        var headers = firstPacket.toString('ascii')
        if (isHttp.test(headers)) {
          this._onhttpConnection(socket, firstPacket, headers)
        } else {
          // other tcp protocols with "name" data in header?
          socket.destroy()
        }
      }
    })
  }

  _ontlsConnection (socket, firstPacket) {
    var name = extractSni(firstPacket)
    var app = this._appByName(name)
    if (!app || !app.machines || !app.ports) {
      socket.destroy()
      return
    }
    socket.app = app
    socket.unshift(firstPacket)
    if (app.tls) {
      this._tlsServer.emit('connection', socket)
    } else {
      this._proxy(socket)
    }
  }

  _onhttpConnection (socket, firstPacket, headers) {
    var host = extractHostHeader.exec(headers)
    var name = host && host[1].split(':')[0]
    var app = this._appByName(name)
    if (!app || !app.machines || !app.ports) {
      socket.end('HTTP/1.1 404 Not Found\r\n\r\nnot found')
      return
    }
    if (app.tls) {
      this._checkDomainValidation(socket, headers, host[1])
      return
    }
    socket.app = app
    socket.unshift(firstPacket)
    if (app.http) {
      this._httpServer.emit('connection', socket)
    } else {
      this._proxy(socket)
    }
  }

  _checkDomainValidation (socket, headers, host) {
    var pathname = headers.slice(headers.indexOf(' ') + 1)
    pathname = pathname.slice(0, pathname.indexOf(' '))
    if (this.isDomainValidationRequest(pathname)) {
      var proof = this.challenges[pathname]
      if (proof) {
        socket.end(`HTTP/1.1 200 OK\r\n\r\n${proof}`)
        this.setChallenge(pathname, null)
        return
      } else {
        socket.end('HTTP/1.1 404 Not Found\r\n\r\nnot found')
      }
    } else {
      socket.end(`HTTP/1.1 302 Found\r\nLocation: https://${host}${pathname}\r\n\r\n`)
    }
  }

  _ontlsConnectionSecure (socket) {
    socket.on('error', err => {
      console.log('TLS ERROR', err)
      socket.destroy()
    })
    var app = socket.app = socket._handle._parentWrap.app // this will probably break
    if (app.http) {
      this._httpServer.emit('connection', socket)
    } else {
      this._proxy(socket)
    }
  }

  _onhttpRequest (req, res) {
    var socket = req.socket
    var app = socket.app
    var host = req.headers.host || ''
    var parts = host.split(':')
    var name = parts[0]
    var port = parts[1]
    if (app.http.cname && name !== app.http.cname) {
      var protocol = app.tls ? 'https' : 'http'
      port = port ? ':' + port : ''
      res.setHeader('location', `${protocol}://${app.http.cname}${port}${req.url}`)
      res.statusCode = 302
      res.end()
      return
    }
    var pre = app.http.pre
    var dest = app
    if (pre) {
      if (typeof pre === 'string') {
        pre = app.http.pre = (new Function(pre))()
      }
      var redirect = pre(req)
      if (typeof redirect === 'string') {
        dest = this.apps[redirect]
      }
    }
    var machine = dest && dest.machines && this.balanceLoad(dest)
    var upstreamAddress = machine && machine.address
    var upstreamPort = dest && dest.ports && dest.ports[socket.localPort]
    if (!upstreamAddress || !upstreamPort) {
      res.statusCode = 503
      res.end('service unavailable')
      return
    }
    var upstream = url.parse(upstreamAddress)
    if (upstream.protocol === null) {
      upstream = {
        protocol: 'http:',
        hostname: upstreamAddress
      }
    }
    var iface = (upstream.protocol === 'https:' ? https : http)
    var uReq = iface.request({
      protocol: upstream.protocol,
      hostname: upstream.hostname,
      port: upstreamPort,
      path: req.url,
      agent: this._httpAgent,
      headers: req.headers
    })
    uReq.on('error', err => {
      res.statusCode = 503
      res.end('service unavailable')
    })
    uReq.on('response', uRes => {
      var post = app.http.post
      if (post) {
        if (typeof post === 'string') {
          post = app.http.post = (new Function(post))()
        }
        post(uRes)
      }
      res.writeHead(
        uRes.statusCode,
        uRes.statusMessage,
        uRes.headers
      )
      uRes.pipe(res)
    })
    req.pipe(uReq)
  }

  _appByName (name) {
    if (!name) return
    var record = this.names[name]
    if (!record) {
      var nameParts = null
      for (var key in this.names) {
        var candidate = this.names[key]
        if (candidate.wild) {
          nameParts = nameParts || name.split('.')
          var keyParts = key.split('.')
          if (keyParts.length === nameParts.length) {
            if (keyParts
              .map((part, i) => part === '*' ? nameParts[i] : keyParts[i])
              .join('.') === name) {
              record = candidate
              break
            }
          }
        }
      }
    }
    var appId = record && record.appId
    if (appId) {
      var app = this.apps[appId]
      if (app) {
        app.id = appId
      }
      return app
    }
  }

  _proxy (socket) {
    var app = socket.app
    var machine = this.balanceLoad(app)
    var upstreamPort = app.ports[socket.localPort]
    var upstreamAddress = machine && machine.address
    if (upstreamAddress && upstreamPort) {
      var upstream = net.connect(upstreamPort, upstreamAddress)
      socket.pipe(upstream).pipe(socket)
    } else {
      socket.destroy()
    }
  }
}
