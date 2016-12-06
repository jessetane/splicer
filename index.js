var EventEmitter = require('events')
var net = require('net')
var tls = require('tls')
var diff = require('object-diff')
var isTls = require('is-tls-client-hello')
var extractSni = require('sni')
var isHttp = / HTTP\/1\.1$/
var extractHostHeader = /\r\nhost: (.+?)(?:\r|$)/i
var extractUserAgent = /\r\nuser-agent: (.+?)(?:\r|$)/i

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
      var httpHeaders = null
      var name = null
      if (wasTls) {
        name = extractSni(data)
      } else {
        httpHeaders = this._parseHttp(data)
        if (httpHeaders) {
          name = httpHeaders.hostname
        }
      }
      var app = this._appByName(name)
      if (app && app.ports && app.machines) {
        socket.servername = name
        socket.unshift(data)
        if (wasTls) {
          this._ontlsConnection(socket, app)
        } else if (httpHeaders) {
          this._onhttpConnection(socket, httpHeaders, app)
        } else {
          socket.destroy()
        }
      } else {
        socket.destroy()
      }
    })
  }

  _parseHttp (packet) {
    packet = packet.toString('ascii')
    var endOfFirstLine = packet.indexOf('\r\n')
    var firstLine = packet.slice(0, endOfFirstLine)
    if (isHttp.test(firstLine)) {
      var headers = packet.slice(0, packet.indexOf('\r\n\r\n'))
      var host = extractHostHeader.exec(headers)
      host = host ? host[1].split(':') : []
      return {
        pathname: firstLine.split(' ')[1],
        hostname: host[0],
        port: host[1]
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

  _onhttpConnection (socket, headers, app) {
    if (app.tls) {
      var pathname = headers.pathname
      if (this.isDomainValidationRequest(pathname)) {
        var proof = this.challenges[pathname]
        if (proof) {
          socket.end(`HTTP/1.1 200 OK\r\n\r\n${proof}`)
          this.setChallenge(pathname, null)
        } else {
          socket.end('HTTP/1.1 404 Not Found\r\n\r\nnot found')
        }
      } else {
        this._redirectHttp(socket, headers, app)
      }
    } else if (app.cname && app.cname !== headers.hostname) {
      this._redirectHttp(socket, headers, app)
    } else {
      this._proxy(socket, app)
    }
  }

  _onsecureConnection (socket) {
    var app = this._appByName(socket.servername)
    if (app) {
      socket.on('error', noop)
      if (app.cname && app.cname !== socket.servername) {
        socket.once('readable', () => {
          var data = socket.read() || new Buffer(0)
          var httpHeaders = this._parseHttp(data)
          if (httpHeaders) {
            this._redirectHttp(socket, httpHeaders, app)
          } else {
            socket.unshift(data)
            this._proxy(socket, app)
          }
        })
      } else {
        this._proxy(socket, app)
      }
    } else {
      socket.destroy()
    }
  }

  _redirectHttp (socket, headers, app) {
    var protocol = app.tls ? 'https' : 'http'
    var hostname = app.cname || headers.hostname
    var port = headers.port ? `:${headers.port}` : ''
    var pathname = headers.pathname
    socket.end(`HTTP/1.1 302 Found\r\nLocation: ${protocol}://${hostname}${port}${pathname}\r\n\r\n`)
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
