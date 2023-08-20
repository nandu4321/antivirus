from hashlib import md5
from operator import le
import time
import os
import sys
import hashlib
import main
from mpui import *




malware_hashes=list(open("DataBase\\HashDataBase\\Sha256\\virusHash.unibit",'r').read().split('\n'))
virusinfo=list(open("DataBase\\HashDataBase\\Sha256\\virusInfo.unibit",'r').read().split('\n'))

def sha256_hash(filename):
    import hashlib
    try:
        with open(filename, "rb") as f:
            bytes = f.read()
            sha256hash = hashlib.sha256(bytes).hexdigest()

            f.close()
        return sha256hash
    except:
        return 0


def malware_checker(pathoffile):
    global malware_hashes
    global virusinfo
    hash_malware_check = sha256_hash(pathoffile)
    counter = 0

    for i in malware_hashes:
        if i == hash_malware_check:
            return virusinfo[counter]
        counter += 1

    return 0

virusname=[]
def folder_scanner():
    path="C:\\Users\\nanda\\Desktop\\test"
    dir_list=list()
    for (dirpath,dirnames,filenames) in os.walk(path):
        dir_list+=[os.path.join(dirpath, file) for file in filenames]
    for i in dir_list:

        print(i)
        if malware_checker(i)!=0:
            virusname.append(malware_checker(i)+":: file ::"+i)




