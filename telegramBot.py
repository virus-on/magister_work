from src.scanner import Scanner
from src.scanResultProcessor import XMLScanProcessor as XMLProcessor
from src.pdfOut import PDFOutput
import telebot
import json
import time
from threading import Timer
from datetime import datetime, timedelta


bot = telebot.TeleBot("")
config = {}
scanner = None
timer = None

scan_is_running = False
scan_should_stop = False


def scan():
    global scan_is_running, scan_should_stop, scanner
    try:
        scan_is_running = True
        keyboard = telebot.types.InlineKeyboardMarkup()
        callback_button_stop = telebot.types.InlineKeyboardButton(text="STOP", callback_data="stop")
        keyboard.add(callback_button_stop)
        bot.send_message(config["tgBot"]["admin_chat_id"], "Scan started!", reply_markup=keyboard)
        print("Scan STARTED!")
        files = scanner.run_scans()
        if not scan_should_stop:
            processor = XMLProcessor()
            for file in files:
                processor.add_scan_file(file)
            pdfOut = PDFOutput("src/templates/title.md", "src/templates/content.md", "result.pdf")
            pdfFile = pdfOut.build_output_doc(processor.cve_tree)
            for chat in config["tgBot"]["subscribed_chats"]:
                with open(pdfFile, "rb") as file:
                    bot.send_document(chat, file)
    except Exception as ex:
        print(ex)
        scanner = Scanner("config.json")
    finally:
        scan_is_running = False
        scan_should_stop = False
        print("Scan finished!")


def save_config(data):
    with open("config.json", "w") as write_file:
        json.dump(data, write_file, indent=4)


def get_schedule_from_config(cfg):
    return int(config["scanConfig"]["scheduleScanParams"]["days_interval"]), int(config["scanConfig"]["scheduleScanParams"]["hours"]), int(config["scanConfig"]["scheduleScanParams"]["minutes"])


def get_seconds_till_next_scan(daysInterval, hours, minutes):
    next_date = datetime.now() + timedelta(daysInterval)
    next_date_time = datetime(year=next_date.year, month=next_date.month, 
                        day=next_date.day, hour=hours, minute=minutes, second=0)
    return (next_date_time - datetime.now()).seconds


def sheclude_next_scan():
    global config, timer
    if "scheduleScanParams" in config["scanConfig"]:
        if not timer is None and timer.is_alive():
            timer.cancel()
        timer = Timer(get_seconds_till_next_scan(*get_schedule_from_config(config)), run_scan_by_timer)
        print("Timer started")
        timer.start()
    else:
        print("No params provided!")


def run_scan_by_timer():
    scan()
    sheclude_next_scan()


@bot.message_handler(commands=['start'])
def start_message(message):
    global config
    try:
        if not "admin_id" in config["tgBot"]:
            config["tgBot"]["admin_id"] = message.from_user.id
            config["tgBot"]["admin_chat_id"] = message.chat.id
            config["tgBot"]["subscribed_chats"] = [message.chat.id]
            save_config(config)
            bot.send_message(message.chat.id, "User registred as admin")
            return

        if not message.chat.id in config["tgBot"]["subscribed_chats"]:
            keyboard = telebot.types.InlineKeyboardMarkup()
            callback_button_accept = telebot.types.InlineKeyboardButton(text="accept", callback_data="accept {0}".format(message.chat.id))
            callback_button_reject = telebot.types.InlineKeyboardButton(text="reject", callback_data="reject {0}".format(message.chat.id))
            keyboard.add(callback_button_accept)
            keyboard.add(callback_button_reject)

            bot.send_message(config["tgBot"]["admin_chat_id"], "User {0} {1} request's subscription".format(message.from_user.first_name, message.from_user.last_name), reply_markup=keyboard)
            bot.send_message(message.chat.id, "Waiting for conformation")
    except Exception as ex:
        print(ex)


@bot.message_handler(commands=['schedule'])
def sheclude_scans(message):
    global config, timer
    try:
        if config["tgBot"]["admin_id"] == message.from_user.id:
            if "discard" in message.text:
                if not timer is None:
                    timer.cancel()
                    timer = None
                    config["scanConfig"].pop("scheduleScanParams", None)
                    save_config(config)
                bot.send_message(message.chat.id, "Regular scans disabled!")
            else:
                processing_ready = message.text.strip().replace("/schedule ", "")
                hours = int(processing_ready.split(":")[0])
                minutes = int(processing_ready.split(":")[1].split(" ")[0])
                interval_days = int(processing_ready.split(":")[1].split(" ")[1])
                if hours < 0 or hours > 23:
                    bot.send_message(message.chat.id, "Invalid hours value provided!")
                elif minutes < 0 or minutes > 59:
                    bot.send_message(message.chat.id, "Invalid minutes value provided!")
                elif interval_days < 0 or interval_days > 120:
                    bot.send_message(message.chat.id, "Invalid days interval value provided!")
                else:
                    config["scanConfig"]["scheduleScanParams"] = {}
                    config["scanConfig"]["scheduleScanParams"]["days_interval"] = interval_days
                    config["scanConfig"]["scheduleScanParams"]["hours"] = hours
                    config["scanConfig"]["scheduleScanParams"]["minutes"] = minutes
                    sheclude_next_scan()
                    save_config(config)
                    bot.send_message(message.chat.id, "Params applyed! Scan will be launched every {0} days at {1}:{2}".format(interval_days, hours, minutes))
    except Exception as ex:
        try:
            bot.send_message(message.chat.id, "Invalid time value!")
        except:
            pass
        print(ex)


@bot.callback_query_handler(func=lambda call: True)
def callback_inline(call):
    global config, scanner
    global scan_is_running, scan_should_stop
    try:
        if "accept" in call.data:
            subscriber_chat_id = int(call.data.split(" ")[1])
            config["tgBot"]["subscribed_chats"].append(subscriber_chat_id)
            save_config(config)
            bot.send_message(subscriber_chat_id, "Your request was accepted by administrator!")
            bot.answer_callback_query(call.id, "User successfully accepted")

        elif "reject" in call.data:
            subscriber_chat_id = int(call.data.split(" ")[1])
            if subscriber_chat_id in config["tgBot"]["subscribed_chats"]:
                config["tgBot"]["subscribed_chats"].remove(subscriber_chat_id)
            save_config(config)
            bot.send_message(subscriber_chat_id, "Your request was rejected by administrator!")
            bot.answer_callback_query(call.id, "User rejected")

        elif "stop" in call.data:
            if scan_is_running:
                scan_should_stop = True
                scanner.terminate = True
                bot.answer_callback_query(call.id, "Scan stopped!")
            else:
                bot.answer_callback_query(call.id, "Scan not running!")

    except Exception as ex:
        print(ex)


@bot.message_handler(commands=['scan'])
def scan_message(message):
    global config, scan_is_running
    try:
        print("Scan")
        pass
        if config["tgBot"]["admin_id"] == message.from_user.id and not scan_is_running:
            scan()
    except Exception as ex:
            print(ex)


@bot.message_handler(commands=['unsubscribe_all'])
def unsubscribe_message(message):
    global config
    try:
        if config["tgBot"]["admin_id"] == message.from_user.id:
            config["tgBot"]["subscribed_chats"].clear()
            config["tgBot"]["subscribed_chats"] = [config["tgBot"]["admin_chat_id"]]
            save_config(config)
            bot.send_message(message.chat.id, "All users unsubscribed!")

    except Exception as ex:
            print(ex)


@bot.message_handler(commands=['echo'])
def echo_message(message):
    global config
    try:
        if config["tgBot"]["admin_id"] == message.from_user.id:
            for chat in config["tgBot"]["subscribed_chats"]:
                bot.send_message(chat, "Echo!")
    except Exception as ex:
        print(ex)


def launch_bot():
    bot.token = config["tgBot"]["apiKey"]
    print("Running")
    bot.polling(none_stop=True, interval=1)


if __name__== "__main__":
    with open("config.json", "r") as config_file:
        config = json.load(config_file)
    scanner = Scanner("config.json")
    sheclude_next_scan()
    launch_bot()