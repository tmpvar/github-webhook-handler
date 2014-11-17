const crypto = require('crypto')
    , bl     = require('bl')


function signBlob (key, blob) {
  return 'sha1=' + crypto.createHmac('sha1', key).update(blob).digest('hex')
}


function create (options) {
  if (typeof options != 'object')
    throw new TypeError('must provide an options object')

  if (typeof options.path != 'string')
    throw new TypeError('must provide a \'path\' option')

  if (typeof options.secret != 'string')
    throw new TypeError('must provide a \'secret\' option')

  return handler


  function handler (req, res, callback) {
    if (req.url !== options.path)
      return callback()

    var sig   = req.headers['x-hub-signature']
      , event = req.headers['x-github-event']
      , id    = req.headers['x-github-delivery']

    if (!sig)
      return callback(new Error('No X-Hub-Signature found on request'))

    if (!event)
      return callback(new Error('No X-Github-Event found on request'))

    if (!id)
      return callback(new Error('No X-Github-Delivery found on request'))

    req.pipe(bl(function (err, data) {
      if (err) {
        return callback(err)
      }

      var obj

      if (sig !== signBlob(options.secret, data))
        return callback(new Error('X-Hub-Signature does not match blob signature'))

      try {
        obj = JSON.parse(data.toString())
      } catch (e) {
        return callback(e)
      }

      res.writeHead(200, { 'content-type': 'application/json' })
      res.end('{"ok":true}')

      callback(null, {
          event   : event
        , id      : id
        , payload : obj
        , url     : req.url
      })

    }))
  }
}


module.exports = create
