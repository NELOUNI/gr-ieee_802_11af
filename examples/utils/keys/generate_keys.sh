#! /bin/sh

## Clean Folder
rm ./rsa*

##################################
#What is the whole darned process?
##################################

#Well that?s a good question. For my purposes, this is what I need to know:
#
#Create a Private Key. These usually end in the file extension ?key? If you already have one, don?t worry - it?s cool, we?ll be using that one.
#
#Create a Certificate Signing Request. These usually end in the extension ?csr?, and you send it to the certificate authority to generate a certificate.
#
#If you?re not going to be using an existing service (usually for pay) as a certificate authority, you can create your own Certificate Authority, or self-sign your certificate.
#
#Submit your CSR to the CA and get the results. If you?re doing it yourself, I?ll tell you how. The CA creates a Certificate file, which ends in ?.crt?.
#
#Take the whole collection of files, keep them somewhere safe, and mash them together to create your PEM file (this is usually just used for email.)
#So. Let?s get started, eh?

#############################
#Step Zero: Basic Assumptions
#############################

#your domain name is domain.tld.
#you have OpenSSL installed.
#you are running some form of Linux. I use Debian.


####################################
# Step One: Create your Private Key
####################################

#Ok, here you?re going to create your key - and treat is as such. You should keep this private, and not shared with anyone.
#
#Now, you have a couple of options here - the first is to create your private key with a password, the other is to make it without one. If you create it with a password, you have to type it in every time your start any server that uses it.
#
#Important: If you create your private key with a password, you can remove it later. I recommend creating your private key with a password, and then removing it every time you need to use it. When you?re done with the key without a password, delete it so it isn?t a security risk.

#with a password
#openssl genrsa -des3 -out domain.tld.encrypted.key 1024

#without a password
#d=$(date '+%m-%d-%y')
#echo $d
openssl genrsa -out $dnsdomainname "rsa.key"

#If you created your private key with a password, you?ll want to complete the rest of the steps using a decrypted private key - else you?ll have to type in your password every time you use the certificate (ie: every time you start a daemon using that certificate.)

#Remove the password and encryption from your private key
#openssl rsa -in domain.tld.encrypted.key -out domain.tld.key

##########################
# Step Two: Create a CSR
##########################

#Create your Certificate Signing Request
openssl req -new -key "rsa.key" -out "rsa.csr"

#####################################
#Step Three: Create your Certificate
#####################################

#You have three options here: 1. Self-signing - Easy, free, and quick. Not trusted by browsers. 2. Creating a certificate authority (CA) - Not difficult, but likely more effort. Still isn?t trusted by browsers. 3. Paying a CA to create your certificate for you. Can be cheap ($20), pretty easy, and is trusted by browsers.
#
#My advice: Self-sign your certificates for personal things, and pay for a certificate if its public and important.
#
#If you?d like to pay for someone to sign your certificates, do some research and find which one you want to use. Next, find their instructions for submitting your CSR file.

#Self-Sign your Certificate
openssl x509 -req -days 365 -in "rsa.csr" -signkey "rsa.key" -out "rsa.crt"

#If you do happen to want to setup your own certificate authority, check these resources out:
#
#http://www.g-loaded.eu/2005/11/10/be-your-own-ca/
#http://codeghar.wordpress.com/2008/03/17/create-a-certificate-authority-and-certificates-with-openssl/

################################
#Step Four: Creating a PEM file
################################

#Many daemons use a PEM file. Directions on how to generate such a PEM file can be hard to come by. I have had pretty good success with combining the .key and the .crt file together:

cat "rsa.key" "rsa.crt" > "rsa.pem"
