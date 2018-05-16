const crypto = require('crypto')
const type = 'AES'

const encrypt = ({
  data,
  key,
  iv = '',
  mode = 'ecb',
  clearEncoding = 'utf8',
  cipherEncoding = 'base64',
  keyEncoding = 'utf8',
  ivEncoding = 'utf8'
} = {}) => {
  if (!data || !key) {
    return ''
  }

  let chunks = []
  let keyBuf = Buffer.from(key, keyEncoding)
  let ivBuf = Buffer.from(iv, ivEncoding)

  let keyLen = keyBuf.byteLength * 8

  if (keyLen != 128 && keyLen != 192 && keyLen != 258) {
    throw new Error('key length is not supported')
  }

  let algorithm = `${type}-${keyLen}-${mode}`.toLowerCase()

  let cipher = crypto.createCipheriv(algorithm, keyBuf, ivBuf)
  cipher.setAutoPadding(true)
  chunks.push(cipher.update(data, clearEncoding, cipherEncoding))
  chunks.push(cipher.final(cipherEncoding))
  return chunks.join('')
}

const decrypt = ({
  data,
  key,
  iv = '',
  mode = 'ecb',
  clearEncoding = 'utf8',
  cipherEncoding = 'base64',
  keyEncoding = 'utf8',
  ivEncoding = 'utf8'
} = {}) => {
  if (!data || !key) {
    return ''
  }

  let chunks = []
  let keyBuf = Buffer.from(key, keyEncoding)
  let ivBuf = Buffer.from(iv, ivEncoding)

  let keyLen = keyBuf.byteLength * 8

  if (keyLen != 128 && keyLen != 192 && keyLen != 258) {
    throw new Error('key length is not supported')
  }

  let algorithm = `${type}-${keyLen}-${mode}`.toLowerCase()

  let cipher = crypto.createDecipheriv(algorithm, keyBuf, ivBuf)
  cipher.setAutoPadding(true)
  chunks.push(cipher.update(data, cipherEncoding, clearEncoding))
  chunks.push(cipher.final(clearEncoding))
  return chunks.join('')
}

module.exports = {
  encrypt,
  decrypt,
  type
}
