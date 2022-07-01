"""
Script to check files in Blacklist
Made by Reatmos
Github : reatmos
Twitter : @Pa1ath
Blog: https://re-atmosphere.tistory.com/
"""

import subprocess

# Set locate for Blacklist
file = 'C:\\WLAV\\BlackList.db'

def OutDB():
    # Set the location of the file to save and the column to load
    subprocess.call(['sqlite3', file, '.output C:/WLAV/Temp/Black.txt', 'SELECT Hash_Value FROM HASH'])