"""
Runs sequence of health checks for given list of hosts and trigger alerting notifications when required.
"""

import os
import ssl
import time
import socket
import argparse
import requests
import urllib3
import json
import smtplib
import traceback
import subprocess

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

urllib3.disable_warnings()

CONFIG = {}


def send_email(subject, body, from_email, to_email, config):
    html = f"""<html><body><pre>{body}</pre></body></html>"""

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = from_email
    message["To"] = to_email
    message.attach(MIMEText(body, "plain"))
    message.attach(MIMEText(html, "html"))

    try:
        server = smtplib.SMTP(config["smtp_host"], config["smtp_port"])
        # server.set_debuglevel(1)
        server.ehlo()
        if config.get("smtp_use_tls"):
            server.starttls(context=ssl.create_default_context())
        server.ehlo()
        server.login(config["smtp_user"], config["smtp_password"])
        server.sendmail(from_email, to_email, message.as_string())
    except Exception:
        traceback.print_exc()
    finally:
        server.quit() 


def send_push_notification(message, config, subscribers_tokens):
    try:
        for token_info in subscribers_tokens:
            requests.post(
                url=config["post_url"],
                json=dict(
                    token=token_info[0],
                    user=token_info[1],
                    message=message,
                )
            )
    except Exception:
        traceback.print_exc()


def send_sms(message, phone_numbers, config):
    request_headers = {
        "Content-Type": "application/json",
        "Authorization": config["auth_token"],
        "X-Version": "1"
    }
    try:
        resp = requests.post(
            url=config["gateway_url"],
            json=dict(text=message, to=phone_numbers),
            headers=request_headers
        )
    except Exception:
        traceback.print_exc()
        return False

    if resp.status_code != 202:
        error_code = resp.json().get("error", {}).get("code")
        error_description = resp.json().get("error", {}).get("description")
        raise Exception(f"sending SMS to {phone_numbers} with message '{message}' returned an error.\n"
                        f"Error code: {error_code}, Error description: {error_description}")

    return True


def prepare_report(history_filename):
    """
    Reads each line from the file and prepare detailed report like that:

           domain1.com        -+++-
             host2.net        +++++
           server3.org        ++-++

    """
    global CONFIG
    report_text = ""
    with open(history_filename, 'r') as health_check_file:
        lines = health_check_file.readlines()
        for index, host in enumerate(CONFIG["hosts"]):
            report_text += "{0:7} {1:30} {2}".format(
                host['host'].split('://')[0],
                host['host'].split('://')[1],
                lines[index],
            )
    return report_text


def single_test(host, method='ping', params=None, verbose=False):
    """
    Executes system `ping` util to check availability of given host.
    """
    if method in ['http', 'https', ]:
        if params:
            try:
                timeout = int(params.get('timeout', 10))
            except:
                timeout = 10
        try:
            req = requests.get('%s://%s' % (method, host, ),  verify=True, timeout=timeout)
            req.raise_for_status()
        except Exception as e:
            if verbose:
                print(method, host, e)
            return False
        if verbose:
            print(method, host, 'OK')
        return True

    if method == 'dnstcp':
        if params:
            try:
                timeout = int(params.get('timeout', 10))
            except:
                timeout = 10
        captive_dns_addr = ""
        try:
            captive_dns_addr = socket.gethostbyname("ThisDomainMustNotExist1234.notexist")
        except:
            pass
        try:
            host_addr = socket.gethostbyname(host)
            if captive_dns_addr and captive_dns_addr == host_addr:
                if verbose:
                    print(method, host, 'DNS PROBE NOT POSSIBLE')
                return False
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, 53))
            s.close()
        except Exception as e:
            if verbose:
                print(method, host, e)
            return False
        if verbose:
            print(method, host, 'OK')
        return True

    if method == 'dns':
        if params:
            try:
                timeout = int(params.get('timeout', 10))
            except:
                timeout = 10
        captive_dns_addr = ""
        try:
            captive_dns_addr = socket.gethostbyname("ThisDomainMustNotExist1234.notexist")
        except:
            pass
        try:
            host_addr = socket.gethostbyname(host)
            if captive_dns_addr and captive_dns_addr == host_addr:
                if verbose:
                    print(method, host, 'DNS PROBE NOT POSSIBLE')
                return False
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b'', (host, 53))
            s.close()
        except Exception as e:
            if verbose:
                print(method, host, e)
            return False
        if verbose:
            print(method, host, 'OK')
        return True

    if method == 'dnsdig':
        proc = subprocess.Popen(f"/bin/dig {host} +short NS", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        _out, _err = proc.communicate()
        ret_code = proc.returncode
        if verbose:
            print(method, host, 'OK' if ret_code == 0 else 'FAIL\n' + _out.decode() + '\n' + _err.decode())
        if ret_code != 0:
            return False
        if params:
            ns_list = params.get('name_servers')
            if ns_list:
                for ns in ns_list:
                    if not _out.decode().count(ns):
                        if verbose:
                            print(f'    nameserver {ns} was not found in the "dig" output')
                        return False
        return True

    if method == 'ping':
        proc = subprocess.Popen(f"/bin/ping -c 1 {host}", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        _out, _err = proc.communicate()
        ret_code = proc.returncode
        if verbose:
            print(method, host, 'OK' if ret_code == 0 else 'FAIL\n' + _out.decode() + '\n' + _err.decode())
        return ret_code == 0

    if method == 'whois':
        cmd = f"/bin/whois {host}"
        if params:
            target_domain_name = params.get('target_domain_name')
            whois_port = params.get('whois_port')
            if target_domain_name and whois_port:
                cmd = f"/bin/whois --host {host} --port {whois_port} {target_domain_name}"
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        _out, _err = proc.communicate()
        _out = _out.decode()
        _err = _err.decode()
        ret_code = proc.returncode
        if verbose:
            print(method, host, 'OK' if ret_code == 0 else 'FAIL\n' + _out + '\n' + _err)
        if ret_code != 0:
            return False
        if not _out.count('Domain Status: active'):
            return False
        return True

    if verbose:
        print(method, host, 'UNKNOWN METHOD')
    return False


def get_method_host(full_host):
    """
    Decides which method to use for given host and returns tuple (method, host). 
    """
    method = 'ping'
    host = str(full_host)
    if host.startswith('http://'):
        method = 'http'
        host = host.replace('http://', '')
    elif host.startswith('https://'):
        method = 'https'
        host = host.replace('https://', '')
    elif host.startswith('ping://'):
        method = 'ping'
        host = host.replace('ping://', '')
    elif host.startswith('dns://'):
        method = 'dns'
        host = host.replace('dns://', '')
    elif host.startswith('dnstcp://'):
        method = 'dnstcp'
        host = host.replace('dnstcp://', '')
    elif host.startswith('dnsdig://'):
        method = 'dnsdig'
        host = host.replace('dnsdig://', '')
    elif host.startswith('whois://'):
        method = 'whois'
        host = host.replace('whois://', '')
    return method, host


def main():
    global CONFIG

    parser = argparse.ArgumentParser(
        prog='simple_monitor',
        description='Monitoring tool for checking connectivity with your remote hosts, sends notifications in case of issues',
        epilog='coded by Veselin Penev aka github.com/vesellov'
    )
    parser.add_argument(
        '-c', '--config',
        required=True,
        help='File path with JSON-formatted config',
    )
    parser.add_argument(
        '-t', '--tests-history',
        required=True,
        help='File path to store tests history',
    )
    parser.add_argument(
        '-v', '--verbose',
        default=False,
        action="store_true",
        help='Log details of the checks to STDOUT',
    )
    args = parser.parse_args()
    verbose = args.verbose
    history_filename = args.tests_history
    CONFIG = json.loads(open(args.config).read())

    if verbose:
        print(time.asctime())

    health_results = ["-", ] * len(CONFIG["hosts"])
    for index, host_info in enumerate(CONFIG["hosts"]):
        method, host = get_method_host(host_info["host"])
        if single_test(host, method, params=host_info, verbose=verbose):
            health_results[index] = "+"
        else:
            if host_info.get('reliable'):
                # When we detect a failed connection towards "reliable" host - stop and exit
                print('connection towards reliable host is broken')
                return False

    # If file is empty, write health results for the first time.
    try:
        file_exists_but_empty = os.stat(history_filename).st_size == 0
        file_does_not_exist = False
    except Exception:
        file_does_not_exist = True
        file_exists_but_empty = False

    # When history file not exists yet, need to create it first and skip furter execution 
    if file_exists_but_empty or file_does_not_exist:
        with open(history_filename, "w") as health_check_file:
            health_check_file.write("\n".join(health_results))
        return

    unhealthy_hosts = []
    hosts_to_be_notified = []
    updated_lines_of_file = ""
    with open(history_filename, 'r') as health_check_file:
        lines = health_check_file.readlines()
        for index, host_info in enumerate(CONFIG["hosts"]):
            if index < len(lines):
                # Add health of the host to its line.
                updated_line = lines[index].strip()+f"{health_results[index]}\n"
                # Do not make any line more than 20 characters.
                if len(updated_line) == CONFIG.get("history_count", 20):
                    updated_line = updated_line[1:]
            else:
                # If there is a new host added after file was created, add new line with the health result
                updated_line = f"{health_results[index]}\n"

            updated_lines_of_file += updated_line
            # If last X amount of health checks are negative, add that host to the unhealthy hosts group.
            if updated_line.split('\n')[0].endswith(CONFIG.get("max_unavailable_count", 3) * '-'):
                unhealthy_hosts.append(host_info["host"])
                if host_info.get("notify_once") or CONFIG.get("notify_once"):
                    # Raise an alert only one time
                    if updated_line.split('\n')[0].endswith('+' + CONFIG.get("max_unavailable_count", 3) * '-'):
                        hosts_to_be_notified.append(host_info["host"])
                else:
                    # If notify_once is not set for that host then we assume we must raise alert every time when it failed
                    hosts_to_be_notified.append(host_info["host"])

    # Update the history file with the new values.
    with open(history_filename, "w") as health_check_file:
        health_check_file.write(updated_lines_of_file)

    alerts = []
    if hosts_to_be_notified:
        hosts_txt_report = prepare_report(history_filename)

        if CONFIG.get("email", {}).get("enabled"):
            for email_address in CONFIG["email"].get("recipients", []):
                alerts.append(('email', email_address, hosts_txt_report, ))
                try:
                    send_email(
                        subject='ALERT: %s' % (', '.join(unhealthy_hosts)),
                        body=hosts_txt_report,
                        from_email=CONFIG["email"]["config"]["from"],
                        to_email=email_address,
                        config=CONFIG["email"]["config"],
                    )
                except:
                    traceback.print_exc()

        if CONFIG.get("sms", {}).get("enabled"):
            alerts.append(('sms', '', hosts_txt_report, ))
            try:
                send_sms(
                    message='ALERT: %s' % (', '.join(unhealthy_hosts)),
                    phone_numbers=CONFIG["sms"]["recipients"],
                    config=CONFIG["sms"]["config"],
                )
            except:
                traceback.print_exc()

        if CONFIG.get("push", {}).get("enabled"):
            alerts.append(('push', '', hosts_txt_report, ))
            try:
                send_push_notification(
                    message='ALERT: %s' % (', '.join(unhealthy_hosts)),
                    config=CONFIG["push"]["config"],
                    subscribers_tokens=CONFIG["push"]["subscribers_tokens"],
                )
            except:
                traceback.print_exc()


if __name__ == '__main__':
    main()
