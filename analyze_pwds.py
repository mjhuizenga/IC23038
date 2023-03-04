import pandas as pd
import re
from datetime import datetime
import hashlib
import argparse
from termcolor import colored
import os.path

class PWD_tool:
    def __init__(self):
        self.pwd_list = pd.read_csv("pwd-Data.csv").PasswordHeader.tolist()
        self.weights1 = [1,-20,2,5,5,-10,-0.01]
        self.weights2 = [1,-20,2,5,5]
        self.bad = 0
    def analyze(self,path):
        if not os.path.isfile(path):
            print("Cannot find file:",path)
            return
        with open(path,"r") as filp:
            print("Score, \t\t\tlen,dict,uniq,num/txt,spec,uname,time,hash")
            first = True
            for line in filp:
                if first:
                    first = False
                else:
                    line = line.split(",")
                    arr = self.analyze_pwd(line[4],line[0],line[5])
                    print("Score:["+str(self.score(arr,self.weights1))+"] Details:",arr)
            print("Bad",self.bad)
    def detailed(self,pwd):
        analysis = [
                self.length(pwd),
                self.dictionary(pwd),
                self.unique_chars(pwd),
                self.num_text(pwd),
                self.spec_chars(pwd),
                self.hash_pwd(pwd)
                ]
        score = self.score(analysis,self.weights2)
        print("Overall Score:",score)
        if score <= 60:
            print(colored("Pretty bad password","red"))
        elif score < 80:
            print(colored("Average strength","yellow"))
        else:
            print(colored("Password strength good","green"))

        print("Length of the password:",analysis[0])
        print("Password in cracking list:",analysis[1])
        print("Number of unique Characters:",analysis[2])
        print("Password has both #s and letters:",analysis[3])
        print("Password has special Characters:",analysis[4])
        print("SHA3-256 of the Password:",analysis[5])

    def analyze_pwd(self,pwd,uname,time):
        analysis = [
                self.length(pwd),
                self.dictionary(pwd),
                self.unique_chars(pwd),
                self.num_text(pwd),
                self.spec_chars(pwd),
                self.uses_uname(pwd,uname),
                self.change_time(time),
                self.hash_pwd(pwd)
                ]
        return analysis
    def length(self,pwd):
        return len(pwd)
    #Easy password or not
    def dictionary(self,pwd):
        if any(pwd == word for word in self.pwd_list):
            print("Bad",pwd)
            self.bad += 1
            return True
        else:
            return False
    #measure range of characters
    def unique_chars(self,pwd):
        return len(set(pwd));
    #test to make sure it has numbers and text
    def num_text(self,pwd):
        if re.search(r'[0-9]+',pwd) and re.search(r'[a-zA-Z]+',pwd):
            return True
        else:
            return False
    #check for special characters
    def spec_chars(self,pwd):
        if re.search(r'[!-/]',pwd) or re.search(r'[{-~]',pwd):
            return True
        else:
            return False
    #contains username?
    def uses_uname(self,pwd,uname):
        if uname.lower() in pwd.lower():
            return True
        else:
            return False
    #time since last change
    def change_time(self,time):
        if time == '':
            return 700
        return (datetime.now() - datetime.strptime(time,"%m/%d/%Y")).days
    def hash_pwd(self,pwd):
        return hashlib.sha3_256(pwd.encode()).hexdigest()
    def score(self,arr,weights):
        sum = 0
        for i in range(len(weights)):
            sum += weights[0] * arr[0]
        return sum

parser = argparse.ArgumentParser(description="analyze_pwds.py")
parser.add_argument('-f',type=str)
parser.add_argument('-p',type=str)
args = parser.parse_args()

#Initiate the tool
cls = PWD_tool()

if args.f:
    cls.analyze(args.f)

if args.p:
    cls.detailed(args.p)
