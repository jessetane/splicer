import EventEmitter from 'events'
import net from 'net'
import tls from 'tls'
import http from 'http'
import https from 'https'
import url from 'url'
import diff from 'object-diff'
import isTls from 'is-tls-client-hello'
import extractSni from 'sni'
import basicAuth from 'basic-auth'
const isHttp = /^.+ .+ HTTP\/1\.1$/m
const extractHostHeader = /\r\nhost: (.+?)(?:\r|$)/i

class Splicer extends EventEmitter {
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
    this.hooks = {}

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
    this._httpAgentOpts = {
      keepAlive: true,
      keepAliveMsecs: this.timeout
    }
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
      delete this.hooks[id]
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
    socket.setNoDelay(true)
    socket.on('error', err => {
      // console.log('TCP ERROR', err)
    })
    var self = this
    var firstPacket = Buffer.alloc(0)
    socket.on('readable', onreadable)
    function onreadable () {
      firstPacket = Buffer.concat([firstPacket, socket.read() || Buffer.alloc(0)])
      const r = isTls(firstPacket)
      if (r > 1) return
      socket.removeListener('readable', onreadable)
      if (r === 1) {
        self._ontlsConnection(socket, firstPacket)
      } else {
        var headers = firstPacket.toString('ascii')
        if (isHttp.test(headers)) {
          self._onhttpConnection(socket, firstPacket, headers)
        } else {
          // other tcp protocols with "name" data in header?
          socket.destroy()
        }
      }
    }
  }

  _ontlsConnection (socket, firstPacket) {
    var name = extractSni(firstPacket)
    var app = this._appByName(name)
    this.emit('request', socket, name, app)
    if (!app || !app.machines || !app.ports) {
      socket.destroy()
      return
    }
    socket.app = app
    socket.unshift(firstPacket)
    if (app.tls.front) {
      this._tlsServer.emit('connection', socket)
    } else {
      socket.setTimeout(this.timeout, () => {
        // console.log('SECURE PASSTHROUGH TIMEOUT')
        socket.destroy()
      })
      this._proxy(socket)
    }
  }

  _resolveCname (name, config) {
    if (!config) return name
    if (typeof config === 'string') return config
    if (config.exceptions && config.exceptions[name]) return name
    if (config.value) return config.value
    return name
  }

  _onhttpConnection (socket, firstPacket, headers) {
    var host = extractHostHeader.exec(headers)
    var name = host && host[1].split(':')[0]
    var app = this._appByName(name)
    this.emit('request', socket, name, app)
    if (!app || !app.machines || !app.ports) {
      socket.end('HTTP/1.1 404 Not Found\r\n\r\nnot found')
      return
    }
    if (app.tls.front) {
      var cname = this._resolveCname(host[1], app.http && app.http.cname)
      var pathname = headers.slice(headers.indexOf(' ') + 1)
      pathname = pathname.slice(0, pathname.indexOf(' '))
      if (this.isAcmeHttpChallenge(pathname)) {
        var proof = this.challenges[pathname]
        if (proof) {
          if (typeof proof === 'string') {
            proof = { string: proof }
            setTimeout(() => {
              this.setAcmeChallenge(pathname, null)
            }, 2 * 60 * 1000)
          }
          proof = proof.string
          socket.end(`HTTP/1.1 200 OK\r\n\r\n${proof}`)
        } else {
          socket.end('HTTP/1.1 404 Not Found\r\n\r\nnot found')
        }
      } else {
        socket.end(`HTTP/1.1 302 Found\r\nLocation: https://${cname}${pathname}\r\n\r\n`)
      }
      return
    }
    socket.app = app
    socket.unshift(firstPacket)
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
    if (!app.http) {
      socket.destroy()
      return
    }
    var host = req.headers.host || ''
    var parts = host.split(':')
    var name = parts[0]
    var port = parts[1]
    var cname = this._resolveCname(name, app.http && app.http.cname)
    if (name !== cname) {
      var protocol = app.tls.front ? 'https' : 'http'
      port = port ? ':' + port : ''
      res.setHeader('location', `${protocol}://${cname}${port}${req.url}`)
      res.statusCode = 302
      res.end()
      return
    }
    var httpAuth = app.http.auth
    if (httpAuth) {
      var auth = basicAuth(req)
      if (!auth || httpAuth[auth.name] !== auth.pass) {
        // this next check shouldn't be necessary but
        // https://bugs.webkit.org/show_bug.cgi?id=80362
        if (auth || req.headers.upgrade !== 'websocket') {
          res.statusCode = 401
          res.setHeader('WWW-Authenticate', `Basic realm="secure area"`)
          res.end('access denied')
          return
        }
      }
    }
    var { pre, post } = app.http
    var hooks = this.hooks[app.id]
    if (pre || post) {
      if (!hooks) {
        hooks = this.hooks[app.id] = {}
      }
      req.parsedUrl = url.parse(req.url, true)
    }
    var dest = app
    if (pre) {
      if (!hooks.pre) {
        hooks.pre = (new Function(pre))()
      }
      var redirect = hooks.pre(req, app)
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
    req.headers['x-forwarded-for'] = socket.remoteAddress
    var transport = http
    var agent = null
    var rejectUnauthorized = true
    if (dest.tls.back) {
      transport = https
      if (!this._httpsAgent) {
        this._httpsAgent = new https.Agent(this._httpAgentOpts)
      }
      agent = this._httpsAgent
      if (dest.tls.back === 'insecure') {
        rejectUnauthorized = false
      }
    } else {
      if (!this._httpAgent) {
        this._httpAgent = new http.Agent(this._httpAgentOpts)
      }
      agent = this._httpAgent
    }
    var opts = {
      hostname: upstreamAddress,
      port: upstreamPort,
      path: req.url,
      headers: req.headers,
      method: req.method,
      agent,
      rejectUnauthorized
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
      if (!app.http) {
        socket.destroy()
        return
      }
      if (post) {
        if (!hooks.post) {
          hooks.post = (new Function(post))()
        }
        hooks.post(uRes, app)
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
    var appId = record?.appId || record
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
        port: upstreamPort,
        servername: upstreamAddress,
        rejectUnauthorized: app.tls.back !== 'insecure'
      })
      upstream.setNoDelay(true)
      upstream.on('error', err => {
        // console.log('UPSTREAM ERROR', err)
      })
      upstream.setTimeout(this.timeout, () => {
        // console.log('UPSTREAM TIMEOUT')
        upstream.destroy()
      })
      socket.pipe(upstream).pipe(socket)
    } else {
      socket.destroy()
    }
  }
}

export default Splicer
