"""
Script to run SHA256 Check Script with cmd
Made by Reatmos
Github : reatmos
Twitter : @Pa1ath
Blog: https://re-atmosphere.tistory.com/
"""

import subprocess
import os

def pyexe():
    cmd = subprocess.Popen("cmd.exe /c chcp 949 && python.exe CheckVT.py")
    cmd.wait()
