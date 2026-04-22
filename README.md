# Detecting Privacy leaks in Android Health Apps

## Description 
This project is for completing a static analysis of android applications in order to provide insight into what security risks these apps have in them.

## Threat Model
Adversaries include Third part sdks, malicious software developers, Analytics and advertising services, and Malicious network attacker.
The goal of the attackers is to recover as much personal identifiable information can be found on a user. This includes location data, authentication data, and healh
related data.
Defender assumpotions are that this is purely an analysis without app execution and that the apks provided are clean and not corrupt


## Setup
A Docker container running an instance of MobSF is required more details on how to set up are here https://github.com/mobsf/mobile-security-framework-mobsf
After running an instance of MobSF keep it running in the background, in analyzer.py change variable API_KEY to your own personal api key lcoated in MobSF
also depending on what port number was sued for MobSF container change variable MOBSF_URL to your poty number(Default is 8000).
After docker setup download the APKs that you wish to test and put them in the apks folder located in the programs root folder. It Supports .apk and .apkm files but .apkm
files are preferred. APKMirror is a trusted site to download APKs.


## How To Run
1. Once the files that you want to analyze are downloaded and in the correct folder open a terminal navigate to the location of analyzer.py and run the command
python analyzer.py. 
2. Program will begin to send all the files to MobSF for analysis this may take a while. 
3. Once analysis is finish in the terminal there will be a total count for risks detected as well as an app by app total. In the pdf_reports folder will be pdf reports of each app and
in json_reports there will be json reports of each app.

## Results
Expected results will differ depending on what apks were inputted however it will always output one json and one pdf per apk that was inputted and it will provide an app analysis in the command
prompt as well.

## Contributors
Alejandro Cancio
Sebastian Menendez
Arul Rosario Antonio Wilson