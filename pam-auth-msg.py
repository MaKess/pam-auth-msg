import traceback
import random
import socket
import json
from smtplib import SMTP
from email.mime.text import MIMEText
import syslog
import os
import configparser

def get_config(user):
    config = configparser.ConfigParser()
    config.read(["/etc/authmsg.conf", os.path.expanduser("~{}/.authmsg.conf".format(user))])
    return config

def send_mail(config, message, subject):
    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = config.get("mail", "from") 
    msg["To"] = config.get("mail", "to")

    conn = SMTP(config.get("mail", "host"), config.getint("mail", "port"))
    conn.ehlo()
    conn.starttls()
    conn.login(config.get("mail", "user"), config.get("mail", "password"))
    conn.sendmail(config.get("mail", "from"), [config.get("mail", "to")], msg.as_string())
    conn.quit()
    return True

def send_sms_huawei(config, message):
    "for usage with HUAWEI 3G stick"

    import requests
    from xml.etree import ElementTree
    from xml.sax.saxutils import escape
    import datetime

    api = "http://192.168.8.1/api"

    escape_content = escape(message)
    date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    data = "<request><Index>-1</Index><Phones><Phone>{phone:s}</Phone></Phones><Sca/><Content>{content:s}</Content><Length>{length:d}</Length><Reserved>1</Reserved><Date>{date:s}</Date></request>".format(
            phone=config.get("sms", "number"),
            content=escape_content,
            length=-1,
            date=date
    )
    session_token_request = requests.get("{}/webserver/SesTokInfo".format(api))
    session_token_root = ElementTree.fromstring(session_token_request.content)
    session = session_token_root.find("SesInfo").text
    token = session_token_root.find("TokInfo").text
    headers = {
            "Cookie": session,
            "X-Requested-With": "XMLHttpRequest",
            "__RequestVerificationToken": token,
            "Content-Type": "text/xml"
    }
    send_request = requests.post("{}/sms/send-sms".format(api), data=data, headers=headers)
    send_root = ElementTree.fromstring(send_request.content)

    return send_root.text == "OK"

def send_sms_com_perfness_smsgateway_rest(config, message):
    "for usage with 'com.perfness.smsgateway.rest'"

    import urllib
    import urllib2

    answer = urllib2.urlopen(url="http://192.168.42.129:8080/v1/sms/",
                             data=urllib.urlencode({"phone": config.get("sms", "number"),
                                                    "message": message})).read()
    return answer == "OK"

def send_sms_fr_nope_smsgateway(config, message):
    "for usage with 'fr.nope.smsgateway'"

    import urllib2

    resp = urllib2.urlopen(urllib2.Request("http://192.168.42.129:8080/",
                                           json.dumps({"number": config.get("sms", "number"),
                                                       "text": message}),
                                           {"Content-Type": "application/json"}))
    answer = json.loads(resp.read())
    return "id" in answer

def send_message(config, message, subject):
    if config.getboolean("send", "mail"):
        try:
            syslog.syslog(syslog.LOG_INFO, "sending e-mail")
            send_mail(config, message, subject)
        except Exception as ex:
            syslog.syslog(syslog.LOG_ERR, traceback.format_exc())
            syslog.syslog(syslog.LOG_ERR, str(ex))

    if config.getboolean("send", "sms"):
        try:
            syslog.syslog(syslog.LOG_INFO, "sending sms")
            return send_sms_huawei(config, message)
        except Exception as ex:
            syslog.syslog(syslog.LOG_ERR, traceback.format_exc())
            syslog.syslog(syslog.LOG_ERR, str(ex))
            return False

def pam_sm_authenticate(pamh, flags, argv):
    syslog.openlog(facility=syslog.LOG_AUTH)

    config = get_config(pamh.user)

    if not config.getboolean("event", "pin"):
        return pamh.PAM_SUCCESS

    try:
        host = socket.getfqdn()
        digits = config.getint("sms", "digits")
        pin = random.randrange(10 ** digits)

        message = "host: {host}\nuser: {user}\nremote: {remote}\none-time PIN: {pin:0{digits:d}d}".format(
                host=host,
                user=pamh.user,
                remote=pamh.rhost,
                pin=pin,
                digits=digits)
        if not send_message(config, message, "{host} login pin".format(host=host)):
            # if we are currently not able to send the SMS, allow the process to continue
            return pamh.PAM_SUCCESS # return pamh.PAM_AUTH_ERR

        message = pamh.Message(pamh.PAM_PROMPT_ECHO_ON, "please enter the one-time PIN: ")
        response = pamh.conversation(message)

        try:
            response_value = int(response.resp)
        except ValueError:
            response_value = None

        return pamh.PAM_SUCCESS if response_value == pin else pamh.PAM_AUTH_ERR

    except Exception as ex:
        syslog.syslog(syslog.LOG_ERR, traceback.format_exc())
        syslog.syslog(syslog.LOG_ERR, str(ex))
        return pamh.PAM_AUTH_ERR

    finally:
        syslog.closelog()

def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, flags, argv):
    syslog.openlog(facility=syslog.LOG_AUTH)

    config = get_config(pamh.user)

    if not config.getboolean("event", "login"):
        return pamh.PAM_SUCCESS

    try:
        host = socket.getfqdn()
        message = "host: {host}\nuser: {user}\nremote: {remote}\nsession: open".format(
                host=host,
                user=pamh.user,
                remote=pamh.rhost)
        send_message(config, message, "{host} session open".format(host=host))
        return pamh.PAM_SUCCESS

    except Exception as ex:
        syslog.syslog(syslog.LOG_ERR, traceback.format_exc())
        syslog.syslog(syslog.LOG_ERR, "%s: %s" % (__name__, ex))
        return pamh.PAM_AUTH_ERR

    finally:
        syslog.closelog()


def pam_sm_close_session(pamh, flags, argv):
    syslog.openlog(facility=syslog.LOG_AUTH)

    config = get_config(pamh.user)

    if not config.getboolean("event", "logout"):
        return pamh.PAM_SUCCESS

    try:
        host = socket.getfqdn()
        message = "host: {host}\nuser: {user}\nremote: {remote}\nsession: close".format(
                host=host,
                user=pamh.user,
                remote=pamh.rhost)
        send_message(config, message, "{host} session close".format(host=host))
        return pamh.PAM_SUCCESS

    except Exception as ex:
        syslog.syslog(syslog.LOG_ERR, traceback.format_exc())
        syslog.syslog(syslog.LOG_ERR, "%s: %s" % (__name__, ex))
        return pamh.PAM_AUTH_ERR

    finally:
        syslog.closelog()


def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS
