# WebChecker
![Generic badge](https://img.shields.io/badge/Version-1.0.0-RED.svg)

**WebChecker** is a simple information gathering tool designed to help pentesters gather information about a target website.
![Screen-Recording-2022-02-04-at-0](https://user-images.githubusercontent.com/43548656/152489199-8c2aa54e-a304-4258-b17b-dc881220cff0.gif)


## Highlights 
**WebChecker** `1.0.0` supports:
- WordPress Identification (4 stages)
- Joomla Identification (1 stage)
- Magento Identification (4 stages)
- Drupal Identification (3 stages)
- **Directory Bruteforcing **
- Detailed Headers Report

## Prerequisites 
**WebChecker** is built with Python 3 and has been tested on MacOS so far.

## Installing WebChecker
To install **WebChecker** on your machine, run the following commands on your terminal:
```
git clone git@github.com:mihneamanolache/WebChecker.git 
cd WebChecker
pip install -r requirements.txt
```

## Using WebChecker
**WebChecker** runs in terminal and can be used both with or without terminal arguments. The arguments it accepts are:
- `-u` or `--url` to specify the targeted URL
- `-b` or `--brute` to discover directories using bruteforce

Command example using arguments:
```
python3 WebChecker.py -u https://scoala.buzz/ -b /Users/laptop/Desktop/Wordlists/directories.txt 
```
![Screenshot 2022-02-04 at 09 14 14](https://user-images.githubusercontent.com/43548656/152487424-79ac30a4-1c72-473d-9ad9-af5319fb20eb.png)

Where `directories.txt` is a simple wordlist which contains the following lines (in this case):
```
login
cpanel
archive
resources
email
wp-content
admin
.httaccess
.httaccess1
passwd
passwords
intranet
```
*Note that you can use any other wordlist (ie. [dnsmap.txt](https://github.com/Blkzer0/Wordlists/blob/master/dnsmap.txt "dnsmap.txt")). Just specify the path to the file after `-b`*

If used withoth the `--url` switch, the program will prompt the user to enter the target website manually:
```
python3 WebChecker.py 
```
![Screenshot 2022-02-04 at 09 17 00](https://user-images.githubusercontent.com/43548656/152487765-e7142232-ddcb-4b7b-b63f-73de940f482b.png)