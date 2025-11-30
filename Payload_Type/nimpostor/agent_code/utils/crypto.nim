## crypto.nim
## Cryptographic utilities for agent communications

import std/[strutils, base64]

when defined(AESPSK):
  # Only compile crypto when AES is enabled
  import nimcrypto/[rijndael, bcmode, hash, hmac, sha2, sysrand]
  
  proc encryptAES256*(plaintext: string, key: string): string =
    ## Encrypt data using AES-256-CBC
    ## Returns Base64 encoded ciphertext with IV prepended
    try:
      # Ensure key is 32 bytes for AES-256
      var keyBytes: array[32, byte]
      let keyHash = sha256.digest(key)
      copyMem(addr keyBytes[0], unsafeAddr keyHash.data[0], 32)
      
      # Generate random IV (16 bytes for AES)
      var iv: array[16, byte]
      if randomBytes(addr iv[0], 16) != 16:
        raise newException(ValueError, "Failed to generate IV")
      
      # Pad plaintext to block size (16 bytes)
      var paddedText = plaintext
      let padLen = 16 - (plaintext.len mod 16)
      for i in 0..<padLen:
        paddedText.add(char(padLen))
      
      # Encrypt
      var ctx: CBC[aes256]
      var encrypted = newSeq[byte](paddedText.len)
      
      ctx.init(keyBytes, iv)
      ctx.encrypt(cast[ptr UncheckedArray[byte]](unsafeAddr paddedText[0]),
                  addr encrypted[0],
                  uint(paddedText.len))
      ctx.clear()
      
      # Prepend IV to encrypted data
      var output = newSeq[byte](16 + encrypted.len)
      copyMem(addr output[0], addr iv[0], 16)
      copyMem(addr output[16], addr encrypted[0], encrypted.len)
      
      # Return base64 encoded
      result = encode(output)
    except:
      result = plaintext  # Fallback to plaintext on error
  
  proc decryptAES256*(ciphertext: string, key: string): string =
    ## Decrypt AES-256-CBC encrypted data
    ## Expects Base64 encoded ciphertext with IV prepended
    try:
      # Decode base64
      let decoded = decode(ciphertext)
      if decoded.len < 16:
        return ciphertext
      
      # Extract IV (first 16 bytes)
      var iv: array[16, byte]
      copyMem(addr iv[0], unsafeAddr decoded[0], 16)
      
      # Extract ciphertext (rest of data)
      let encryptedLen = decoded.len - 16
      var encrypted = newSeq[byte](encryptedLen)
      copyMem(addr encrypted[0], unsafeAddr decoded[16], encryptedLen)
      
      # Ensure key is 32 bytes
      var keyBytes: array[32, byte]
      let keyHash = sha256.digest(key)
      copyMem(addr keyBytes[0], unsafeAddr keyHash.data[0], 32)
      
      # Decrypt
      var ctx: CBC[aes256]
      var decrypted = newSeq[byte](encryptedLen)
      
      ctx.init(keyBytes, iv)
      ctx.decrypt(addr encrypted[0],
                  addr decrypted[0],
                  uint(encryptedLen))
      ctx.clear()
      
      # Remove PKCS7 padding
      let padLen = int(decrypted[^1])
      if padLen > 0 and padLen <= 16:
        result = newString(decrypted.len - padLen)
        copyMem(addr result[0], addr decrypted[0], decrypted.len - padLen)
      else:
        result = cast[string](decrypted)
    except:
      result = ciphertext  # Fallback to returning input on error
  
  proc generateHMAC*(message: string, key: string): string =
    ## Generate HMAC-SHA256 for message authentication
    var hmacCtx: HMAC[sha256]
    var keyData = key.toOpenArrayByte(0, key.len - 1)
    var msgData = message.toOpenArrayByte(0, message.len - 1)
    
    hmacCtx.init(keyData)
    hmacCtx.update(msgData)
    let digest = hmacCtx.finish()
    
    result = encode($digest)
  
  proc verifyHMAC*(message: string, key: string, expectedHmac: string): bool =
    ## Verify HMAC-SHA256
    let calculated = generateHMAC(message, key)
    result = calculated == expectedHmac

else:
  # Stub implementations when encryption is disabled
  proc encryptAES256*(plaintext: string, key: string): string =
    result = plaintext
  
  proc decryptAES256*(ciphertext: string, key: string): string =
    result = ciphertext
  
  proc generateHMAC*(message: string, key: string): string =
    result = ""
  
  proc verifyHMAC*(message: string, key: string, expectedHmac: string): bool =
    result = true
