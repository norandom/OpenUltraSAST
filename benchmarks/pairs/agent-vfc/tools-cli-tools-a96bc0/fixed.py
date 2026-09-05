# Provenance: D-sorganization/Tools  (fixed).
# repo: D-sorganization/Tools
# commit: a96bc0502a3dcdac303e4f0152508886e5c35c0a
# parent: e735d28b82dd1fbc42c0ae01157b38d1b4c7c864
# commit_url: https://github.com/D-sorganization/Tools/commit/a96bc0502a3dcdac303e4f0152508886e5c35c0a
# cve: 
# license: MIT
# function: _is_command_allowed
# relpath: src/shared/python/ai/tools/cli_tools.py
# provenance: agent
# mechanism: source_reaches_sink

    def _is_command_allowed(self, command: str) -> bool:
        """Check if a command is allowed.

        Args:
            command: Command to check.

        Returns:
            True if allowed, False otherwise.
        """
        # Dangerous commands are never allowed
        dangerous = ["rm", "sudo", "chmod", "chown", "curl", "wget", "ssh"]

        # Prevent shell injection by blocking command separators/operators
        shell_operators = ["&&", "||", ";", "|", ">", "<", "$", "`", "\n", "&"]
        if any(op in command for op in shell_operators):
            return False

        try:
            tokens = shlex.split(command)
            if not tokens:
                return False

            # Verify the first token is in the allowlist
            base_cmd = tokens[0]
            if base_cmd not in self._allowed_commands:
                return False

            # Verify no token is a dangerous command
            for token in tokens:
                if token in dangerous:
                    return False

                try:
                    # Check for absolute/relative paths (e.g., /bin/rm, ./rm)
                    if Path(token).name in dangerous:
                        return False

                    # Check for assignments passing executables (e.g., --exec=/bin/rm)
                    if "=" in token:
                        val = token.split("=", 1)[1]
                        if val in dangerous or Path(val).name in dangerous:
                            return False
                except Exception:
                    pass

            return True
        except ValueError:
            # e.g., missing closing quote
            return False
