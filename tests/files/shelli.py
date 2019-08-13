import subprocess


def vulnerable(infile):
    subprocess.Popen(['command.exe', infile], shell=True)
