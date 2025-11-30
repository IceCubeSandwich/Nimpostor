import asyncio
import json
import logging
import os
import sys
import tempfile
import traceback
import zipfile
from distutils.dir_util import copy_tree

from mythic_payloadtype_container.PayloadBuilder import *
from mythic_payloadtype_container.MythicRPC import *
from mythic_payloadtype_container.MythicCommandBase import *

# Attempt importing optional modules
try:
    sys.path.insert(1, "/opt")
    import ShellcodeRDI
except Exception:
    ShellcodeRDI = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class Nimble(PayloadType):

    name = "nimble"
    file_extension = "zip"
    author = "@0xtb"
    mythic_encrypts = True
    supported_os = [SupportedOS.Windows, SupportedOS.Linux]
    wrapper = False
    wrapped_payloads = []
    note = "A Nim-based agent for Stage-1 C2 operations with httpx support."
    supports_dynamic_loading = True

    build_parameters = [
        BuildParameter(
            name="os",
            parameter_type=BuildParameterType.ChooseOne,
            description="Target operating system.",
            choices=["windows", "linux"],
            default_value="windows"
        ),
        BuildParameter(
            name="arch",
            parameter_type=BuildParameterType.ChooseOne,
            description="Target architecture.",
            choices=["x64", "x86"],
            default_value="x64"
        ),
        BuildParameter(
            name="format",
            parameter_type=BuildParameterType.ChooseOne,
            description="Output format.",
            choices=["exe", "dll", "bin"],
            default_value="exe"
        ),
        BuildParameter(
            name="build_type",
            parameter_type=BuildParameterType.ChooseOne,
            description="Debug or release build.",
            choices=["release", "debug"],
            default_value="release"
        ),
        BuildParameter(
            name="chunk_size",
            parameter_type=BuildParameterType.String,
            description="Message chunk size (bytes) for httpx.",
            default_value="512000",
            required=False,
        ),
        BuildParameter(
            name="default_proxy",
            parameter_type=BuildParameterType.Boolean,
            description="Use system default proxy.",
            default_value=False,
            required=False
        ),
    ]

    c2_profiles = ["httpx", "http"]

    support_browser_scripts = [
        BrowserScript(script_name="copy_additional_info_to_clipboard", author="@djhohnstein"),
        BrowserScript(script_name="create_table", author="@djhohnstein"),
        BrowserScript(script_name="create_table_with_name", author="@djhohnstein"),
        BrowserScript(script_name="collapsable", author="@djhohnstein"),
        BrowserScript(script_name="create_process_additional_info_modal", author="@djhohnstein"),
        BrowserScript(script_name="file_size_to_human_readable_string", author="@djhohnstein"),
        BrowserScript(script_name="integrity_level_to_string", author="@djhohnstein"),
        BrowserScript(script_name="show_process_additional_info_modal", author="@djhohnstein"),
        BrowserScript(script_name="show_permission_additional_info_modal", author="@djhohnstein"),
    ]

    # ------------------------------------------------------------------
    # Construct compilation command
    # ------------------------------------------------------------------
    def _build_nim_command(self, build_path: str, aespsk_val: str, params: dict, profile_name: str) -> list:
        arch_flag = "amd64" if params["arch"] == "x64" else "i386"

        os_flags = []
        if params["os"] == "linux":
            os_flags = ["--os:linux", "--passL:-W", "--passL:-ldl"]

        build_flags = (
            ["-d:debug", "--hints:on", f"--nimcache:{build_path}"]
            if params["build_type"] == "debug"
            else ["-d:release", "--hints:off"]
        )

        format_flags = []
        if params["format"] in ("dll", "bin"):
            format_flags = ["--app:lib", "--nomain"]

        # Define which C2 profile to compile
        profile_flag = []
        if profile_name == "httpx":
            profile_flag = ["-d:HTTPX_PROFILE"]
        elif profile_name == "http":
            profile_flag = ["-d:HTTP_PROFILE"]

        aes_flag = [f"-d:AESPSK={aespsk_val}"] if aespsk_val else []

        out_ext = ".dll" if params["format"] in ("dll", "bin") else ".exe"

        cmd = [
            "nim",
            "--threads:on",
            "--gc:arc",
            "--tlsEmulation:on",
            "c",
            "-f",
            *os_flags,
            *build_flags,
            *profile_flag,
            *aes_flag,
            "--opt:size",
            "--passC:-flto",
            "--passL:-flto",
            "--passL:-s",
            *format_flags,
            "--embedsrc:on" if params["build_type"] == "debug" else "",
            f"--cpu:{arch_flag}",
            f"--out:{self.name}{out_ext}",
            "agent_code/c2/base.nim",
        ]

        # clean empty items
        return [arg for arg in cmd if arg]

    # ------------------------------------------------------------------
    # Generate httpx configuration
    # ------------------------------------------------------------------
    def _generate_httpx_config(self, c2_params: dict) -> dict:
        """
        Extract httpx-specific configuration from Mythic C2 parameters.
        """
        config = {
            "callback_host": c2_params.get("callback_host", ""),
            "callback_port": c2_params.get("callback_port", 443),
            "callback_interval": c2_params.get("callback_interval", 10),
            "callback_jitter": c2_params.get("callback_jitter", 50),
            "encrypted_exchange_check": c2_params.get("encrypted_exchange_check", True),
            "domain_front": c2_params.get("domain_front", ""),
            "get_uri": c2_params.get("get_uri", "/api/v1/status"),
            "post_uri": c2_params.get("post_uri", "/api/v1/data"),
            "query_path_name": c2_params.get("query_path_name", "q"),
            "proxy_host": c2_params.get("proxy_host", ""),
            "proxy_port": c2_params.get("proxy_port", ""),
            "proxy_user": c2_params.get("proxy_user", ""),
            "proxy_pass": c2_params.get("proxy_pass", ""),
            "killdate": c2_params.get("killdate", ""),
            "headers": {},
        }

        # Process headers
        if "headers" in c2_params:
            if isinstance(c2_params["headers"], list):
                for header in c2_params["headers"]:
                    if "key" in header and "value" in header:
                        config["headers"][header["key"]] = header["value"]
            elif isinstance(c2_params["headers"], dict):
                config["headers"] = c2_params["headers"]

        return config

    # ------------------------------------------------------------------
    # Build process
    # ------------------------------------------------------------------
    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Error)
        temp_dir = None

        try:
            # Setup workspace
            temp_dir = tempfile.TemporaryDirectory(suffix=self.uuid)
            build_root = temp_dir.name

            copy_tree(self.agent_code_path, build_root)

            if not self.c2info:
                resp.build_message = "No C2 profile information provided."
                return resp

            c2 = self.c2info[0]
            profile_name = c2.get_c2profile().get("name")

            if profile_name not in self.c2_profiles:
                resp.build_message = f"Unsupported C2 profile '{profile_name}'. Supported: {', '.join(self.c2_profiles)}"
                return resp

            params = self.get_parameter_dict()

            # Get C2 parameters
            c2_params = c2.get_parameters_dict()
            
            # AES key
            aespsk_val = ""
            if isinstance(c2_params.get("AESPSK"), dict):
                aespsk_val = c2_params["AESPSK"].get("enc_key", "")

            # -------------------------
            # Update configuration file
            # -------------------------
            config_path = os.path.join(build_root, "agent_code", "utils", "config.nim")

            if not os.path.exists(config_path):
                resp.build_message = "config.nim not found in agent_code/utils directory."
                return resp

            with open(config_path, "r") as cfg:
                config_data = cfg.read()

            # Prepare configuration replacements
            replacements = {
                "%CHUNK_SIZE%": params.get("chunk_size", "512000"),
                "%DEFAULT_PROXY%": str(params.get("default_proxy", False)).lower(),
                "%PAYLOAD_UUID%": self.uuid,
                "%C2_PROFILE%": profile_name,
            }

            # Profile-specific configuration
            if profile_name == "httpx":
                httpx_config = self._generate_httpx_config(c2_params)
                
                replacements.update({
                    "%CALLBACK_HOST%": httpx_config["callback_host"],
                    "%CALLBACK_PORT%": str(httpx_config["callback_port"]),
                    "%CALLBACK_INTERVAL%": str(httpx_config["callback_interval"]),
                    "%CALLBACK_JITTER%": str(httpx_config["callback_jitter"]),
                    "%GET_URI%": httpx_config["get_uri"],
                    "%POST_URI%": httpx_config["post_uri"],
                    "%QUERY_PATH_NAME%": httpx_config["query_path_name"],
                    "%DOMAIN_FRONT%": httpx_config["domain_front"],
                    "%PROXY_HOST%": httpx_config["proxy_host"],
                    "%PROXY_PORT%": str(httpx_config["proxy_port"]) if httpx_config["proxy_port"] else "",
                    "%PROXY_USER%": httpx_config["proxy_user"],
                    "%PROXY_PASS%": httpx_config["proxy_pass"],
                    "%KILLDATE%": httpx_config["killdate"],
                    "%HEADERS%": json.dumps(httpx_config["headers"]),
                    "%ENCRYPTED_EXCHANGE_CHECK%": str(httpx_config["encrypted_exchange_check"]).lower(),
                })
            
            elif profile_name == "http":
                # Standard HTTP profile configuration
                replacements.update({
                    "%CALLBACK_HOST%": c2_params.get("callback_host", ""),
                    "%CALLBACK_PORT%": str(c2_params.get("callback_port", 443)),
                    "%CALLBACK_INTERVAL%": str(c2_params.get("callback_interval", 10)),
                    "%CALLBACK_JITTER%": str(c2_params.get("callback_jitter", 50)),
                })

            # Apply all replacements
            for placeholder, value in replacements.items():
                config_data = config_data.replace(placeholder, str(value))

            # Handle any remaining C2 parameters
            for key, value in c2_params.items():
                if not isinstance(value, dict):
                    placeholder = f"%{key}%"
                    if placeholder in config_data:
                        config_data = config_data.replace(
                            placeholder, 
                            json.dumps(value) if not isinstance(value, str) else value
                        )

            with open(config_path, "w") as cfg:
                cfg.write(config_data)

            logging.info(f"Config file updated for profile: {profile_name}")

            # -------------------------
            # Compile
            # -------------------------
            cmd = self._build_nim_command(build_root, aespsk_val, params, profile_name)
            logging.info(f"Running Nim command: {' '.join(cmd)}")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=build_root
            )

            stdout, stderr = await proc.communicate()
            resp.build_message = (
                "[NIM STDOUT]\n" + stdout.decode() +
                "\n[NIM STDERR]\n" + stderr.decode()
            )

            if proc.returncode != 0:
                resp.build_message = f"Nim build failed ({proc.returncode}).\n" + resp.build_message
                return resp

            # -------------------------
            # Packaging
            # -------------------------
            ext = ".dll" if params["format"] in ("dll", "bin") else ".exe"
            artifact_path = os.path.join(build_root, f"{self.name}{ext}")
            zip_path = os.path.join(build_root, f"{self.name}.zip")

            if not os.path.exists(artifact_path):
                resp.build_message = "Expected build output missing."
                return resp

            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                if params["format"] == "bin":
                    if ShellcodeRDI is None:
                        resp.build_message = "ShellcodeRDI module not available for bin format."
                        return resp

                    with open(artifact_path, "rb") as f:
                        dll_bytes = f.read()

                    shellcode = ShellcodeRDI.ConvertToShellcode(
                        dll_bytes,
                        ShellcodeRDI.HashFunctionName("Run"),
                        flags=0x5
                    )
                    zf.writestr("loader.bin", shellcode)
                else:
                    zf.write(artifact_path, os.path.basename(artifact_path))

            # -------------------------
            # Finalize
            # -------------------------
            with open(zip_path, "rb") as z:
                resp.payload = z.read()

            resp.status = BuildStatus.Success
            resp.build_message = f"Payload built successfully with {profile_name} profile."
            return resp

        except Exception as e:
            resp.build_message = (
                f"Unexpected build error: {e}\n" + traceback.format_exc()
            )
            return resp

        finally:
            if temp_dir:
                temp_dir.cleanup()
