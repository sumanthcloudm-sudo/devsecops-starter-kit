# Intentionally vulnerable examples for security-scanner testing only.
# Do not use this code in production.

import subprocess


def run_user_command(user_input):
    # Unsafe: shell=True with untrusted input can allow command injection.
    subprocess.run(user_input, shell=True, check=False)


def evaluate_expression(expression):
    # Unsafe: eval() can execute arbitrary Python code.
    return eval(expression)
