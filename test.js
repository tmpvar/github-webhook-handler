const test     = require('tape')
    , crypto   = require('crypto')
    , handler  = require('./')
    , through2 = require('through2')


function signBlob (key, blob) {
  return 'sha1=' +
  crypto.createHmac('sha1', key).update(blob).digest('hex')
}


function mkReq (url) {
  var req = through2()
  req.url = url
  req.headers = {
      'x-hub-signature'   : 'bogus'
    , 'x-github-event'    : 'bogus'
    , 'x-github-delivery' : 'bogus'
  }
  return req
}


function mkRes () {
  var res = {
      writeHead : function (statusCode, headers) {
        res.$statusCode = statusCode
        res.$headers = headers
      }

    , end       : function (content) {
        res.$end = content
      }
  }

  return res
}


test('handler without full options throws', function (t) {
  t.plan(4)

  t.equal(typeof handler, 'function', 'handler exports a function')

  t.throws(handler, /must provide an options object/, 'throws if no options')

  t.throws(handler.bind(null, {}), /must provide a 'path' option/, 'throws if no path option')

  t.throws(handler.bind(null, { path: '/' }), /must provide a 'secret' option/, 'throws if no secret option')
})


test('handler ignores invalid urls', function (t) {
  var options = { path: '/some/url', secret: 'bogus' }
    , h       = handler(options)

  t.plan(9)

  h(mkReq('/'), mkRes(), function (err, event) {
    t.error(err)
    t.ok(true, 'request was ignored')
    t.ok(!event, 'ensure the event is not propagated')
  })

  // near match
  h(mkReq('/some/url/'), mkRes(), function (err, event) {
    t.error(err)
    t.ok(true, 'request was ignored')
    t.ok(!event, 'ensure the event is not propagated')
  })

  // partial match
  h(mkReq('/some'), mkRes(), function (err, event) {
    t.error(err)
    t.ok(true, 'request was ignored')
    t.ok(!event, 'ensure the event is not propagated')
  })
})


test('handler accepts valid urls', function (t) {
  var options = { path: '/some/url', secret: 'bogus' }
    , h       = handler(options)

  t.plan(1)

  h(mkReq('/some/url'), mkRes(), function (err) {
    t.error(err)
    t.fail(false, 'should not call')
  })

  setTimeout(t.ok.bind(t, true, 'done'))
})


test('handler accepts a signed blob', function (t) {
  t.plan(5)

  var obj  = { some: 'github', object: 'with', properties: true }
    , json = JSON.stringify(obj)
    , h    = handler({ path: '/', secret: 'bogus' })
    , req  = mkReq('/')
    , res  = mkRes()

  req.headers['x-hub-signature'] = signBlob('bogus', json)
  req.headers['x-github-event']  = 'push'

  h(req, res, function (err, event) {
    t.ok(!err)
    t.deepEqual(event, { event: 'push', id: 'bogus', payload: obj, url: '/' })
    t.equal(res.$statusCode, 200, 'correct status code')
    t.deepEqual(res.$headers, { 'content-type': 'application/json' })
    t.equal(res.$end, '{"ok":true}', 'got correct content')
  })

  req.end(json)
})

test('handler accepts a signed blob with alt event', function (t) {
  t.plan(5)

  var obj  = { some: 'github', object: 'with', properties: true }
    , json = JSON.stringify(obj)
    , h    = handler({ path: '/', secret: 'bogus' })
    , req  = mkReq('/')
    , res  = mkRes()

  req.headers['x-hub-signature'] = signBlob('bogus', json)
  req.headers['x-github-event']  = 'issue'

  h(req, res, function (err, event) {
    t.error(err)

    t.deepEqual(event, { event: 'issue', id: 'bogus', payload: obj, url: '/' })
    t.equal(res.$statusCode, 200, 'correct status code')
    t.deepEqual(res.$headers, { 'content-type': 'application/json' })
    t.equal(res.$end, '{"ok":true}', 'got correct content')
  })

  req.end(json)
})


test('handler rejects a badly signed blob', function (t) {
  t.plan(2)

  var obj  = { some: 'github', object: 'with', properties: true }
    , json = JSON.stringify(obj)
    , h    = handler({ path: '/', secret: 'bogus' })
    , req  = mkReq('/')
    , res  = mkRes()

  req.headers['x-hub-signature'] = signBlob('bogus', json)
  // break signage by a tiny bit
  req.headers['x-hub-signature'] = '0' + req.headers['x-hub-signature'].substring(1)

  h(req, res, function (err, event) {
    t.equal(err.message, 'X-Hub-Signature does not match blob signature')
    t.ok(!event)
  })

  req.end(json)
})
