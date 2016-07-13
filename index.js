var EventEmitter = require('events')
var net = require('net')
var tls = require('tls')
var http = require('http')
var diff = require('object-diff')
var isTls = require('is-tls-client-hello')
var extractSni = require('sni')
var isHttp = / HTTP\/1\.1$/
var extractHostHeader = /\r\nhost: (.+?)(?:\r|$)/i

module.exports = class Terminus extends EventEmitter {
  constructor (opts = {}) {
    super()

    // how did es6 classes not get a syntax for this?
    var toBind = [
      'onappchange',
      '_ontcpConnection',
      '_onhttpRequest',
      '_ontlsConnection'
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

    // http server to handle domain validation
    this._httpServer = new http.Server()
    this._httpServer.on('request', this._onhttpRequest)

    // tls terminator if necessary
    this.shouldTerminateTls = opts.shouldTerminateTls
    if (this.shouldTerminateTls) {
      this._tlsServer = new tls.Server({
        SNICallback: (name, cb) => this.SNICallback(name, cb)
      })
      this._tlsServer.on('secureConnection', this._ontlsConnection)
    }

    // outward facing tcp listeners
    this.acmeValidationPort = opts.acmeValidationPort || '80'
    this._tcpListeners = {
      // we always listen on 80 for potential domain validation challenges from our CA
      [this.acmeValidationPort]: this._createTcpListener(this.acmeValidationPort)
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
        credential.context = new tls.SecureContext({
          key: credential.key,
          cert: credential.cert
        })
      }
      cb(null, credential.context)
    } else {
      cb(new Error('not found'))
    }
  }

  isDomainValidationRequest (req) {
    return false
  }

  setChallenge (key, value) {
    return false
  }

  balanceLoad (socket, app) {
    return this.machines[Object.keys(app.machines)[0]]
  }

  _appByName (name) {
    name = this.names[name]
    var appId = name && name.appId
    return appId && this.apps[appId]
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
      var data = socket.read()
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
      if (app) {
        socket.servername = name
        socket.unshift(data)
        if (wasTls) {
          if (app.tls) {
            if (this.shouldTerminateTls) {
              this._tlsServer.emit('connection', socket)
            } else {
              this.SNICallback(name, (err, context) => {
                if (err) return socket.destroy()
                this._proxy(socket, app)
              })
            }
          } else {
            this._proxy(socket, app)
          }
        } else if (httpHeaders) {
          if (app.tls) {
            this._httpServer.emit('connection', socket)
          } else {
            this._proxy(socket, app)
          }
        } else {
          socket.destroy()
        }
      } else {
        socket.destroy()
      }
    })
  }

  _onhttpRequest (req, res) {
    if (this.isDomainValidationRequest(req)) {
      var proof = this.challenges[req.url]
      if (proof) {
        res.end(proof)
        this.setChallenge(req.url, null)
      } else {
        res.statusCode = 404
        res.end('not found')
      }
    } else {
      res.statusCode = 302
      res.setHeader('location', `https://${res.socket.servername}${req.url}`)
      res.end()
    }
  }

  _ontlsConnection (socket) {
    var app = this._appByName(socket.servername)
    if (app) {
      this._proxy(socket, app)
    } else {
      socket.destroy()
    }
  }

  _proxy (socket, app) {
    var machine = this.balanceLoad(socket, app)
    var backendAddress = machine && machine.address
    var backendPort = app.ports[socket.localPort]
    if (backendAddress && backendPort) {
      var backend = net.connect(backendPort, backendAddress)
      socket.pipe(backend).pipe(socket)
    } else {
      socket.destroy()
    }
  }
}
