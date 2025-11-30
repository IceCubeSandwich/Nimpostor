## test_config.nim
## Configuration for local testing (replace config.nim for testing)

# Agent UUID
const PAYLOAD_UUID* = "test-uuid-12345678"

# C2 Profile Selection
const C2_PROFILE* = "httpx"

# Common Configuration
const CHUNK_SIZE* = 512000
const DEFAULT_PROXY* = false

# HTTPX Profile Configuration
when defined(HTTPX_PROFILE):
  const CALLBACK_HOST* = "127.0.0.1"
  const CALLBACK_PORT* = 7443
  const CALLBACK_INTERVAL* = 10
  const CALLBACK_JITTER* = 50
  const GET_URI* = "/api/v1/status"
  const POST_URI* = "/api/v1/data"
  const QUERY_PATH_NAME* = "q"
  const DOMAIN_FRONT* = ""
  const ENCRYPTED_EXCHANGE_CHECK* = false
  const HEADERS* = """{"User-Agent": "Mozilla/5.0"}"""
  
  # Proxy Configuration
  const PROXY_HOST* = ""
  const PROXY_PORT* = ""
  const PROXY_USER* = ""
  const PROXY_PASS* = ""
  
  # Killdate
  const KILLDATE* = ""

# HTTP Profile Configuration (standard)
when defined(HTTP_PROFILE):
  const CALLBACK_HOST* = "127.0.0.1"
  const CALLBACK_PORT* = 7443
  const CALLBACK_INTERVAL* = 10
  const CALLBACK_JITTER* = 50

# AES Encryption Key (disabled for testing)
# when defined(AESPSK):
#   const AESPSK* = "test-key-not-for-production"
