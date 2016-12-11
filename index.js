var EventEmitter = require('events')
var net = require('net')
var tls = require('tls')
var http = require('http')
var https = require('https')
var url = require('url')
var diff = require('object-diff')
var isTls = require('is-tls-client-hello')
var extractSni = require('sni')
var isHttp = /^.+ .+ HTTP\/1\.1$/m
var extractHostHeader = /\r\nhost: (.+?)(?:\r|$)/i
var basicAuth = require('basic-auth')

module.exports = class Splicer extends EventEmitter {
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

    // tls terminator
    this._tlsServer = new tls.Server({
      SNICallback: (name, cb) => this.SNICallback(name, cb)
    })
    this._tlsServer.on('secureConnection', this._ontlsConnectionSecure)

    // http server
    this._httpServer = new http.Server()
    this._httpServer.on('request', this._onhttpRequest)
    this._httpServer.on('upgrade', this._onhttpRequest)
    this._httpAgent = new http.Agent({
      keepAlive: true,
      keepAliveMsecs: this.timeout
    })
  }

  close () {
    this._tlsServer.close()
    this._httpServer.close()
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
      if (port === '*') continue
      var listener = this._tcpListeners[port]
      if (listener && --listener.apps === 0) {
        delete this._tcpListeners[port]
        listener.close()
        this.emit('tcpunbind', port)
      }
    }
    for (port in newPorts) {
      if (port === '*') continue
      listener = this._tcpListeners[port]
      if (listener) {
        listener.apps++
      } else {
        this._tcpListeners[port] = this._createTcpListener(port)
      }
    }
    newData.tls = newData.tls && typeof newData.tls === 'object'
      ? newData.tls
      : { front: newData.tls || false, back: false }
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

  isAcmeHttpChallenge (pathname) {
    return false
  }

  setAcmeChallenge (key, value) {
    // user may implement
  }

  balanceLoad (app) {
    var firstMachine = Object.keys(app.machines)[0]
    return this.machines[firstMachine]
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
    if (app.tls.front) {
      this._tlsServer.emit('connection', socket)
    } else {
      socket.setNoDelay(true)
      socket.on('error', err => {
        // console.log('SECURE PASSTHROUGH ERROR', err)
      })
      socket.setTimeout(this.timeout, () => {
        // console.log('SECURE PASSTHROUGH TIMEOUT')
        socket.destroy()
      })
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
    if (app.tls.front) {
      var pathname = headers.slice(headers.indexOf(' ') + 1)
      pathname = pathname.slice(0, pathname.indexOf(' '))
      if (this.isAcmeHttpChallenge(pathname)) {
        var proof = this.challenges[pathname]
        if (proof) {
          this.setAcmeChallenge(pathname, null)
          socket.end(`HTTP/1.1 200 OK\r\n\r\n${proof}`)
        } else {
          socket.end('HTTP/1.1 404 Not Found\r\n\r\nnot found')
        }
      } else {
        socket.end(`HTTP/1.1 302 Found\r\nLocation: https://${host[1]}${pathname}\r\n\r\n`)
      }
      return
    }
    socket.app = app
    socket.unshift(firstPacket)
    socket.setNoDelay(true)
    socket.on('error', err => {
      // console.log('INSECURE HTTP ERROR', err)
    })
    socket.setTimeout(this.timeout, () => {
      // console.log('INSECURE HTTP TIMEOUT')
      socket.destroy()
    })
    if (app.http) {
      this._httpServer.emit('connection', socket)
    } else {
      this._proxy(socket)
    }
  }

  _ontlsConnectionSecure (socket) {
    var app = socket.app = socket._handle._parentWrap.app // this will probably break
    socket.setNoDelay(true)
    socket.on('error', err => {
      // console.log('SECURE ERROR', err)
    })
    socket.setTimeout(this.timeout, () => {
      // console.log('SECURE TIMEOUT')
      socket.destroy()
    })
    if (app.http) {
      this._httpServer.emit('connection', socket)
    } else {
      this._proxy(socket)
    }
  }

  _onhttpRequest (req, res) {
    var socket = req.socket
    var app = this.apps[socket.app.id]
    if (!app) {
      res.statusCode = 404
      res.end('not found')
      return
    }
    var host = req.headers.host || ''
    var parts = host.split(':')
    var name = parts[0]
    var port = parts[1]
    if (app.http.cname && name !== app.http.cname) {
      var protocol = app.tls.front ? 'https' : 'http'
      port = port ? ':' + port : ''
      res.setHeader('location', `${protocol}://${app.http.cname}${port}${req.url}`)
      res.statusCode = 302
      res.end()
      return
    }
    var httpAuth = app.http.auth
    if (httpAuth) {
      var auth = basicAuth(req)
      if (!auth || httpAuth[auth.name] !== auth.pass) {
        res.statusCode = 401
        res.setHeader('WWW-Authenticate', `Basic realm="${name}"`)
        res.end('access denied')
        return
      }
    }
    var { pre, post } = app.http
    if (pre || post) {
      req.parsedUrl = url.parse(req.url, true)
    }
    var dest = app
    if (pre) {
      if (typeof pre === 'string') {
        pre = app.http.pre = (new Function('require', pre))(require)
      }
      var redirect = pre(req, app)
      if (typeof redirect === 'string') {
        dest = this.apps[redirect]
      }
    }
    var machine = dest && dest.machines && this.balanceLoad(dest)
    var upstreamAddress = machine && machine.address
    var upstreamPort = dest && dest.ports && (dest.ports[socket.localPort] || dest.ports['*'])
    if (!upstreamAddress || !upstreamPort) {
      res.statusCode = 503
      res.end('service unavailable')
      return
    }
    req.headers['X-Forwarded-For'] = socket.remoteAddress
    var transport = (dest.tls.back ? https : http)
    var opts = {
      hostname: upstreamAddress,
      port: upstreamPort,
      path: req.url,
      agent: this._httpAgent,
      headers: req.headers,
      method: req.method
    }
    var uReq = transport.request(opts)
    uReq.on('error', err => {
      res.statusCode = 503
      res.end('service unavailable')
    })
    uReq.on('response', onresponse)
    uReq.on('upgrade', onresponse)
    req.pipe(uReq)
    function onresponse (uRes, uSocket) {
      if (post) {
        if (typeof post === 'string') {
          post = app.http.post = (new Function('require', post))(require)
        }
        post(uRes, app)
      }
      var connection = uRes.headers.connection
      if (connection && connection.toLowerCase() === 'upgrade') {
        var headers = ''
        for (var name in uRes.headers) {
          headers += `${name}: ${uRes.headers[name]}\r\n`
        }
        var head = `HTTP/1.1 ${uRes.statusCode} ${uRes.statusMessage}\r\n${headers}\r\n`
        res.write(head)
        uSocket.pipe(res).pipe(uSocket)
      } else {
        res.writeHead(
          uRes.statusCode,
          uRes.statusMessage,
          uRes.headers
        )
        uRes.pipe(res)
      }
    }
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
    var upstreamAddress = machine && machine.address
    var upstreamPort = app.ports[socket.localPort]
    if (!upstreamPort) {
      upstreamPort = app.ports['*']
    }
    if (upstreamAddress && upstreamPort) {
      var transport = app.tls.back ? tls : net
      var upstream = transport.connect({
        host: upstreamAddress,
        port: upstreamPort
      })
      upstream.setNoDelay(true)
      upstream.on('error', err => {
        // console.log('UPSTREAM ERROR', err)
      })
      socket.pipe(upstream).pipe(socket)
    } else {
      socket.destroy()
    }
  }
}
