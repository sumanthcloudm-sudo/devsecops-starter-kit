import subprocess


def print_message(user_input):
    subprocess.run("echo " + user_input, shell=True, check=False)
