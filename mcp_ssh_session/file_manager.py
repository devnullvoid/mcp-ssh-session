"""File management for SSH sessions."""
import base64
import logging
import os
import posixpath
import shlex
import stat
from typing import Optional

import paramiko


class FileManager:
    """Manages file operations on SSH sessions."""

    def __init__(self, session_manager):
        self._session_manager = session_manager
        self.logger = logging.getLogger('ssh_session.file_manager')

    def read_file(self, host: str, remote_path: str, username: Optional[str] = None,
                  password: Optional[str] = None, key_filename: Optional[str] = None,
                  port: Optional[int] = None, encoding: str = "utf-8",
                  errors: str = "replace", max_bytes: Optional[int] = None,
                  sudo_password: Optional[str] = None, use_sudo: bool = False) -> tuple[str, str, int]:
        """Read a remote file over SSH using SFTP, with optional sudo fallback."""
        logger = self.logger.getChild('read_file')
        logger.info(f"Reading remote file on {host}: {remote_path}")

        if not remote_path:
            logger.error("Remote path must be provided.")
            return "", "Remote path must be provided", 1

        # Apply environment variable override for sudo password
        if not sudo_password and use_sudo:
            sudo_password = os.getenv(f"OVRD_{host}_SUDO_PASS")

        _, _, _, _, session_key = self._session_manager._resolve_connection(host, username, port)
        client = self._session_manager.get_or_create_session(host, username, password, key_filename, port)

        byte_limit = self._session_manager.MAX_FILE_TRANSFER_SIZE
        if max_bytes is not None:
            byte_limit = min(max_bytes, self._session_manager.MAX_FILE_TRANSFER_SIZE)
        logger.debug(f"Byte limit set to {byte_limit}")

        used_encoding = encoding or "utf-8"
        used_errors = errors or "replace"

        # Try SFTP first
        sftp = None
        permission_denied = False
        try:
            logger.debug("Attempting to read file via SFTP.")
            sftp = client.open_sftp()
            resolved_path = self._resolve_sftp_path(sftp, remote_path)
            attrs = sftp.stat(resolved_path)
            if stat.S_ISDIR(attrs.st_mode):
                logger.error(f"Remote path is a directory: {resolved_path}")
                return "", f"Remote path is a directory: {resolved_path}", 1

            with sftp.file(resolved_path, "rb") as remote_file:
                data = remote_file.read(byte_limit + 1)
            logger.debug(f"Read {len(data)} bytes via SFTP.")

            truncated = len(data) > byte_limit
            if truncated:
                data = data[:byte_limit]
                logger.warning(f"File content truncated to {byte_limit} bytes.")

            try:
                content = data.decode(used_encoding, used_errors)
            except UnicodeDecodeError as e:
                logger.error(f"Decode error reading file {resolved_path} on {session_key}: {str(e)}")
                return "", f"Failed to decode file using encoding '{used_encoding}': {str(e)}", 1

            stderr_msg = ""
            if truncated:
                stderr_msg = (
                    f"Content truncated to {byte_limit} bytes. Increase max_bytes to retrieve full file."
                )
                content += f"\n\n[CONTENT TRUNCATED after {byte_limit} bytes]"

            logger.info(f"Successfully read file {resolved_path} via SFTP.")
            return content, stderr_msg, 0
        except FileNotFoundError:
            logger.error(f"Remote file not found: {remote_path}")
            return "", f"Remote file not found: {remote_path}", 1
        except PermissionError:
            logger.warning(f"SFTP permission denied for {remote_path}.")
            permission_denied = True
        except Exception as e:
            if 'permission denied' in str(e).lower():
                logger.warning(f"SFTP permission denied for {remote_path}.")
                permission_denied = True
            else:
                logger.error(f"Error reading file {remote_path} on {session_key}: {str(e)}", exc_info=True)
                return "", f"Error reading remote file: {str(e)}", 1
        finally:
            if sftp:
                try:
                    sftp.close()
                except Exception:
                    pass

        # Fallback to sudo if permission denied and use_sudo or sudo_password provided
        if permission_denied and (use_sudo or sudo_password):
            logger.info(f"SFTP permission denied, falling back to sudo cat for {remote_path}")
            # Use head to limit output size
            cmd = f"sudo cat {shlex.quote(remote_path)} | head -c {byte_limit}"
            logger.debug(f"Sudo fallback command: {cmd}")

            if sudo_password:
                stdout, stderr, exit_code = self._session_manager.execute_command(
                    host=host, username=username, password=password, key_filename=key_filename,
                    port=port, command=cmd, sudo_password=sudo_password, timeout=30
                )
            else:
                stdout, stderr, exit_code = self._session_manager.execute_command(
                    host=host, username=username, password=password, key_filename=key_filename,
                    port=port, command=cmd, timeout=30
                )

            if exit_code != 0:
                logger.error(f"Sudo fallback failed for {remote_path}: {stderr}")
                return "", f"Permission denied and sudo failed: {stderr}", exit_code

            # Check if output was truncated
            truncated = len(stdout.encode('utf-8')) >= byte_limit
            if truncated:
                stdout += f"\n\n[CONTENT TRUNCATED after {byte_limit} bytes]"
                stderr_msg = f"Content truncated to {byte_limit} bytes. Increase max_bytes to retrieve full file."
            else:
                stderr_msg = ""
            
            logger.info(f"Successfully read file {remote_path} via sudo fallback.")
            return stdout, stderr_msg, 0
        elif permission_denied:
            logger.error(f"Permission denied reading {remote_path} and no sudo fallback specified.")
            return "", "Permission denied reading file. Set use_sudo=True or provide sudo_password to retry with sudo.", 1

        logger.error("Unexpected error in read_file logic.")
        return "", "Unexpected error in read_file", 1


    def write_file(self, host: str, remote_path: str, content: str,
                   username: Optional[str] = None, password: Optional[str] = None,
                   key_filename: Optional[str] = None, port: Optional[int] = None,
                   encoding: str = "utf-8", errors: str = "strict",
                   append: bool = False, make_dirs: bool = False,
                   permissions: Optional[int] = None,
                   max_bytes: Optional[int] = None,
                   sudo_password: Optional[str] = None, use_sudo: bool = False) -> tuple[str, str, int]:
        """Write content to a remote file over SSH using SFTP, with optional sudo fallback."""
        logger = self.logger.getChild('write_file')
        logger.info(f"Writing remote file on {host}: {remote_path} (append={append})")

        if not remote_path:
            logger.error("Remote path must be provided.")
            return "", "Remote path must be provided", 1

        # Apply environment variable override for sudo password
        if not sudo_password and use_sudo:
            sudo_password = os.getenv(f"OVRD_{host}_SUDO_PASS")

        used_encoding = encoding or "utf-8"
        used_errors = errors or "strict"

        try:
            data = content.encode(used_encoding, used_errors)
        except Exception as e:
            logger.error(f"Failed to encode content using encoding '{used_encoding}': {e}")
            return "", f"Failed to encode content using encoding '{used_encoding}': {str(e)}", 1

        byte_limit = self._session_manager.MAX_FILE_TRANSFER_SIZE
        if max_bytes is not None:
            byte_limit = min(max_bytes, self._session_manager.MAX_FILE_TRANSFER_SIZE)
        logger.debug(f"Byte limit set to {byte_limit}")

        if len(data) > byte_limit:
            logger.error(f"Content size {len(data)} exceeds limit {byte_limit}.")
            return "", (
                f"Content size {len(data)} bytes exceeds maximum allowed {byte_limit} bytes. "
                "Split the write into smaller chunks."
            ), 1

        _, _, _, _, session_key = self._session_manager._resolve_connection(host, username, port)
        client = self._session_manager.get_or_create_session(host, username, password, key_filename, port)

        # Try SFTP first if not explicitly using sudo
        if not use_sudo and not sudo_password:
            sftp = None
            try:
                logger.debug("Attempting to write file via SFTP.")
                sftp = client.open_sftp()
                resolved_path = self._resolve_sftp_path(sftp, remote_path)

                if make_dirs:
                    directory = posixpath.dirname(resolved_path)
                    self._ensure_remote_dirs(sftp, directory)

                mode = "ab" if append else "wb"
                logger.debug(f"Opening remote file in mode '{mode}'.")
                with sftp.file(resolved_path, mode) as remote_file:
                    remote_file.write(data)
                    remote_file.flush()

                if permissions is not None:
                    logger.debug(f"Setting permissions to {oct(permissions)}.")
                    sftp.chmod(resolved_path, permissions)

                message = f"Wrote {len(data)} bytes to {resolved_path}"
                if append:
                    message += " (append)"
                logger.info(f"Successfully wrote file via SFTP: {message}")
                return message, "", 0
            except FileNotFoundError:
                logger.error(f"Remote path not found: {remote_path}")
                return "", f"Remote path not found: {remote_path}", 1
            except PermissionError:
                logger.warning(f"SFTP permission denied for {remote_path}. Will try sudo if configured.")
                return "", "Permission denied writing file. Set use_sudo=True or provide sudo_password to retry with sudo.", 1
            except Exception as e:
                if 'permission denied' in str(e).lower():
                    logger.warning(f"SFTP permission denied for {remote_path}. Will try sudo if configured.")
                    return "", "Permission denied writing file. Set use_sudo=True or provide sudo_password to retry with sudo.", 1
                logger.error(f"Error writing file {remote_path} on {session_key}: {str(e)}", exc_info=True)
                return "", f"Error writing remote file: {str(e)}", 1
            finally:
                if sftp:
                    try:
                        sftp.close()
                    except Exception:
                        pass

        # Use sudo shell commands
        logger.info(f"Using sudo to write {remote_path}")

        # Helper to execute with or without password
        def exec_sudo(cmd: str) -> tuple[str, str, int]:
            return self._session_manager.execute_command(
                host=host, username=username, password=password, key_filename=key_filename,
                port=port, command=cmd, sudo_password=sudo_password, timeout=30
            )

        # Create parent directories if needed
        if make_dirs:
            directory = posixpath.dirname(remote_path)
            if directory and directory != '/':
                mkdir_cmd = f"sudo mkdir -p {shlex.quote(directory)}"
                logger.debug(f"Executing mkdir command: {mkdir_cmd}")
                _, stderr, exit_code = exec_sudo(mkdir_cmd)
                if exit_code != 0:
                    logger.error(f"Failed to create directories with sudo: {stderr}")
                    return "", f"Failed to create directories: {stderr}", exit_code

        # Write content using tee (supports both write and append)
        # Use base64 encoding to avoid shell escaping issues with special characters
        try:
            encoded_content = base64.b64encode(content.encode(used_encoding, used_errors)).decode('ascii')

            if append:
                cmd = f'echo "{encoded_content}" | base64 -d | sudo tee -a {shlex.quote(remote_path)} > /dev/null'
            else:
                cmd = f'echo "{encoded_content}" | base64 -d | sudo tee {shlex.quote(remote_path)} > /dev/null'
            logger.debug(f"Executing write command (base64 encoded): {cmd[:100]}...")
        except Exception as e:
            logger.error(f"Failed to encode content for safe writing: {e}")
            return "", f"Failed to encode content for safe writing: {e}", 1

        stdout, stderr, exit_code = exec_sudo(cmd)

        if exit_code != 0:
            logger.error(f"Failed to write file with sudo: {stderr}")
            return "", f"Failed to write file with sudo: {stderr}", exit_code

        # Set permissions if specified
        if permissions is not None:
            chmod_cmd = f"sudo chmod {oct(permissions)[2:]} {shlex.quote(remote_path)}"
            logger.debug(f"Executing chmod command: {chmod_cmd}")
            _, stderr, exit_code = exec_sudo(chmod_cmd)
            if exit_code != 0:
                logger.warning(f"Failed to set permissions: {stderr}")

        message = f"Wrote {len(data)} bytes to {remote_path} using sudo"
        if append:
            message += " (append)"
        if not sudo_password:
            message += " (passwordless)"
        logger.info(f"Successfully wrote file via sudo: {message}")
        return message, "", 0

    def _resolve_sftp_path(self, sftp: paramiko.SFTPClient, remote_path: str) -> str:
        """Resolve SFTP path, including '~' expansion."""
        if remote_path == "~":
            return sftp.normalize(".")
        if remote_path.startswith("~/"):
            home = sftp.normalize(".")
            return posixpath.join(home, remote_path[2:])
        return remote_path


    def _ensure_remote_dirs(self, sftp: paramiko.SFTPClient, remote_dir: str):
        """Ensure remote directory structure exists when writing files."""
        logger = self.logger.getChild('ensure_dirs')
        if not remote_dir or remote_dir in (".", "/"):
            return

        logger.debug(f"Ensuring remote directory exists: {remote_dir}")
        directories = []
        current = remote_dir

        while current and current not in (".", "/"):
            directories.append(current)
            next_dir = posixpath.dirname(current)
            if next_dir == current:
                break
            current = next_dir

        for directory in reversed(directories):
            try:
                attrs = sftp.stat(directory)
                if not stat.S_ISDIR(attrs.st_mode):
                    logger.error(f"Remote path exists and is not a directory: {directory}")
                    raise IOError(f"Remote path exists and is not a directory: {directory}")
            except FileNotFoundError:
                logger.info(f"Creating remote directory: {directory}")
                sftp.mkdir(directory)
