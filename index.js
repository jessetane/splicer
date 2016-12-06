var EventEmitter = require('events')
var net = require('net')
var tls = require('tls')
var diff = require('object-diff')
var isTls = require('is-tls-client-hello')
var extractSni = require('sni')
var isHttp = / HTTP\/1\.1$/

module.exports = class Terminus extends EventEmitter {
  constructor (opts = {}) {
    super()

    // how did es6 classes not get syntax for this?
    var toBind = [
      'onappchange',
      '_ontcpConnection',
      '_onsecureConnection'
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

    // tls terminator if necessary
    this.shouldTerminateTls = opts.shouldTerminateTls
    if (this.shouldTerminateTls) {
      this._tlsServer = new tls.Server({
        SNICallback: (name, cb) => this.SNICallback(name, cb)
      })
      this._tlsServer.on('secureConnection', this._onsecureConnection)
    }
  }

  close () {
    this._httpServer.close()
    this._tlsServer.close()
    for (var port in this._tcpListeners) {
      this._tcpListeners[port].close()
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

  balanceLoad (socket, app) {
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
    socket.setTimeout(this.timeout, () => socket.destroy())
    socket.setNoDelay(true)
    socket.on('error', noop)
    socket.once('readable', () => {
      var data = socket.read() || new Buffer(0)
      var wasTls = isTls(data)
      var httpMeta = null
      var name = null
      if (wasTls) {
        name = extractSni(data)
      } else {
        httpMeta = this._parseHttp(data)
        if (httpMeta) {
          name = httpMeta.hostname
        }
      }
      var app = this._appByName(name)
      if (app && app.ports && app.machines) {
        if (wasTls) {
          socket.app = app
          socket.unshift(data)
          this._ontlsConnection(socket, app)
        } else if (httpMeta) {
          this._onhttpConnection(socket, httpMeta, app)
        } else {
          socket.destroy()
        }
      } else {
        socket.destroy()
      }
    })
  }

  _parseHttp (data) {
    var string = data.toString('ascii')
    var endOfFirstLine = string.indexOf('\r\n')
    var firstLine = string.slice(0, endOfFirstLine)
    if (isHttp.test(firstLine)) {
      var endOfHeaders = string.indexOf('\r\n\r\n')
      if (endOfHeaders === -1) {
        console.error('HTTP request received but headers did not fit in first packet')
        return
      }
      var meta = {
        firstLine,
        requestBody: data.slice(endOfHeaders + 4)
      }
      var headers = {}
      string
        .slice(endOfFirstLine + 2, endOfHeaders)
        .split('\r\n')
        .forEach(line => {
          var mid = line.indexOf(':')
          if (mid === -1) return
          var name = line.slice(0, mid)
          var value = line.slice(mid + 1)
          headers[name.trim().toLowerCase()] = value.trim()
        })
      var firstLineParts = firstLine.split(' ')
      var host = headers.host
      host = host ? host.split(':') : []
      meta.method = firstLineParts[0]
      meta.pathname = firstLineParts[1]
      meta.protocol = firstLineParts[2]
      meta.hostname = host[0]
      meta.port = host[1]
      meta.headers = headers
      meta.raw = data
      return meta
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
    return appId && this.apps[appId]
  }

  _ontlsConnection (socket, app) {
    if (app.tls) {
      if (this.shouldTerminateTls) {
        this._tlsServer.emit('connection', socket)
      } else if (this.acmeValidationPort) {
        this.SNICallback(name, (err, context) => {
          if (err) return socket.destroy()
          this._proxy(socket, app)
        })
      } else {
        this._proxy(socket, app)
      }
    } else {
      this._proxy(socket, app)
    }
  }

  _onhttpConnection (socket, httpMeta, app) {
    if (app.tls) {
      var pathname = httpMeta.pathname
      if (this.isDomainValidationRequest(pathname)) {
        var proof = this.challenges[pathname]
        if (proof) {
          socket.end(`HTTP/1.1 200 OK\r\n\r\n${proof}`)
          this.setChallenge(pathname, null)
        } else {
          socket.end('HTTP/1.1 404 Not Found\r\n\r\nnot found')
        }
      } else {
        this._redirectHttp(socket, httpMeta, app)
      }
    } else {
      var http = app.http
      if (http) {
        if (http.cname && http.cname !== httpMeta.hostname) {
          this._redirectHttp(socket, httpMeta, app)
          return
        }
        if (http.pre) {
          app = this._preprocessHttp(app, httpMeta)
          socket.unshift(this._reconstructHttp(httpMeta))
        } else {
          socket.unshift(httpMeta.raw)
        }
      } else {
        socket.unshift(httpMeta.raw)
      }
      this._proxy(socket, app)
    }
  }

  _onsecureConnection (socket) {
    var app = socket._handle._parentWrap.app // this will probably break
    socket.setTimeout(this.timeout, () => socket.destroy())
    socket.setNoDelay(true)
    socket.on('error', noop)
    var http = app.http
    if (!http) {
      this._proxy(socket, app)
      return
    }
    socket.once('readable', () => {
      var data = socket.read() || new Buffer(0)
      var httpMeta = this._parseHttp(data)
      if (!httpMeta) {
        socket.destroy()
        return
      }
      if (http.cname && http.cname !== socket.servername) {
        this._redirectHttp(socket, httpMeta, app)
        return
      }
      if (http.pre) {
        app = this._preprocessHttp(app, httpMeta)
        socket.unshift(this._reconstructHttp(httpMeta))
      } else {
        socket.unshift(data)
      }
      this._proxy(socket, app)
    })
  }

  _redirectHttp (socket, httpMeta, app) {
    var protocol = app.tls ? 'https' : 'http'
    var hostname = app.http && app.http.cname || httpMeta.hostname
    var port = httpMeta.port ? `:${httpMeta.port}` : ''
    var pathname = httpMeta.pathname
    socket.end(`HTTP/1.1 302 Found\r\nLocation: ${protocol}://${hostname}${port}${pathname}\r\n\r\n`)
  }

  _preprocessHttp (app, httpMeta) {
    var pre = app.http.pre
    if (typeof pre === 'string') {
      pre = app.http.pre = (new Function(pre))()
    }
    var redirect = pre(httpMeta)
    if (typeof redirect === 'string') {
      var otherApp = this.apps[redirect]
      if (otherApp && otherApp.ports && otherApp.machines) {
        app = otherApp
      }
    }
    return app
  }

  _reconstructHttp (httpMeta) {
    var { method, pathname, protocol, headers } = httpMeta
    var header = `${method} ${pathname} ${protocol}\r\n`
    for (var name in headers) {
      header += `${name}: ${headers[name]}\r\n`
    }
    header += '\r\n'
    return Buffer.concat([
      new Buffer(header, 'ascii'),
      httpMeta.requestBody
    ])
  }

  _proxy (socket, app) {
    var machine = this.balanceLoad(socket, app)
    var backendAddress = machine && machine.address
    var backendPort = app.ports[socket.localPort]
    if (backendAddress && backendPort) {
      var backend = net.connect(backendPort, backendAddress)
      backend.on('error', noop)
      socket.pipe(backend).pipe(socket)
    } else {
      socket.destroy()
    }
  }
}

function noop () {}
