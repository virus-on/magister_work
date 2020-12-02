# TelegramScannerBot

TelegramScannerBot is a tool that enables you to run scans of your network using telegram bot as an interface.   
It can:
 - Run shecluded scans
 - Use different scan configurations
 - It is easy to install and use (see Installation section)
 - Can be hosted in a Docker Container
 - Generate PDF reports
 - Send Reports to multiple subscribers
 
 ## Installation
 You will need to get Telegram bot token from [BotFather](t.me/BotFather). It's a simple process details of which can be found [here](https://core.telegram.org/bots#6-botfather).
 After you acquired Telegram Bot token, Clone this repository to your folder, and run:
 
    > python3 configure.py
After that your actions will depend on weather you want to run Bot in Docker image.
If your answer is yes, you will need to install [Docker](https://docs.docker.com/engine/install/).
After that simply open your console in folder above the scanner and run:

    > docker build -t scanner_bot:v0.1 magister_work
And full functional Docker image with your bot will be ready.
To launch it type:

    > docker run -d -P scanner_bot:v0.1

 ### If you don't want to use Docker container
 Then you will need to install nmap and it's vulners script.
 On Debian based systems it's simply:
 

    > sudo apt install nmap
    > git clone https://github.com/vulnersCom/nmap-vulners.git /usr/share/nmap/scripts/vulners
    > nmap --script-updatedb
And you are ready to go!
To launch bot just run `python3 ./telegramBot.py`

## How to use bot
### Commands List

 - `/start` request subscription from bot admin, first user to call `/start` will be considered as admin
 - `/schedule hours:minutes interval in days`  will schedule scan once per interval days at hours:minutes. E.g. `/schedule 9:30 1` means scan every day at 9:30 AM.
 - `/schedule discard` to disable schedule'd scans
 - `/scan` will launch scaning instantly
 - `/unsubscribe_all` will umsubscribe all subscribers
 - `/echo` Sends "Echo!" message to all subscribers