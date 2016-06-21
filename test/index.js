var tape = require('tape')
var http = require('http')
var Terminus = require('../')

var server = new Terminus({
  hostsPath: __dirname + '/hosts'
})

tape('simple', t => {
  t.plan(1)

  server.once('listen', address => {
    t.equal(address, ':::9000')
    http.request({
      hostname: 'localhost',
      port: '9000',
    })
      // .on('error', () => {})
      .on('response', res => {
        res.on('data', d => {
          t.equal(d.toString(), 'ok')
        })
        res.on('end', () => {
          server.close()
        })
      })
      .end()
  })
})
