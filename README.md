# simple-healthcheck

This is a monitoring tool for checking connectivity with your remote hosts, it sends notifications in case of issues.

The `simple_healthcheck` script runs sequence of health checks for given list of hosts.

When some of your hosts are not passing sequentially few health checks script triggers alerting notification for you.

Script holds history of the health checks in a text file, every next run of the `simple_healthcheck` generates new record in the history file.

        usage: simple_healthcheck.py [-h] -c CONFIG -t TESTS_HISTORY [-v]


        optional arguments:
          -h, --help            show this help message and exit
          -c CONFIG, --config CONFIG
                                File path with JSON-formatted config
          -t TESTS_HISTORY, --tests-history TESTS_HISTORY
                                File path to store tests history
          -v, --verbose         Log details of the checks to STDOUT

        coded by Veselin Penev aka github.com/vesellov



## install

Clone the repository:

        git clone https://github.com/datahaven-net/simple-healthcheck.git
        cd simple-healthcheck



## notifications

Currently 3 types of alerting notifications are implemented.

* email via SMTP protocol
* sms via clickatell.com
* push notification via pushover.net

To configure notifications you need to provide connection details in the `config.json` file, see bellow for more information.



## health checks

There are few different protocols for health checks currently implemented that can be used to monitor your remote hosts:

* `http`: single HTTP request will be sent to the provided host and response is expected to be HTTP 200 status code
* `https`: single HTTPS request will be sent to the provided host and response is expected to be HTTP 200 status code
* `ping`: host will be verified with `/bin/ping` system call
* `dns`: host will be tested with socket connection using `SOCK_DGRAM` protocol (UDP)
* `dnstcp`: host will be tested with socket connection using `SOCK_STREAM` protocol (TCP)
* `dnsdig`: host will be tested with `/bin/dig` system call



## configuration

Create a JSON file with configuration details.

In the `"hosts"` section of the config JSON you will list all of the hosts that needs to be tested.
Each record in that list is a dictionary with such items:

* `"host": "<protocol>://<address>"` is a mandatory item that defines the health check method and the target address
* `"notify_once": <true/false>` is an optional item with default value `false`, set this to `true` if you would like to be notified only once when address is not reachable
* `"reliable": <true/false>` is an optional item with default value `false`, set this to `true` and the script will not produce any alerts when this address is not reachable. This is usefull if machine where the `simple-healthcheck` is executing is not stable or also have issues with internet connection - prevents false-positive alerts. 

Other sections of the config are: `"email"`, `"sms"` and `"push"`. There you define details of the alerts that will be triggered.

Here is a sample file for you:

        cat config.json
        {
            "history_count": 20,
            "max_unavailable_count": 3,
            "email": {
                "enabled": true,
                "config": {
                    "from": "my-outgoing-email@is-here",
                    "smtp_host": "<SMTP host>",
                    "smtp_user": "<SMTP user>",
                    "smtp_password": "<SMTP password>",
                    "smtp_port": 587,
                    "smtp_use_tls": true,
                    "smtp_use_ssl": false
                },
                "recipients": [
                    "first-email-to-receive-notifications@gmail.com",
                    "second-email-to-receive-notifications@gmail.com"
                ]
            },
            "sms": {
                "enabled": true,
                "config": {
                    "auth_token": "bearer <clickatell TOKEN>",
                    "gateway_url": "https://api.clickatell.com/rest/message"
                },
                "recipients": [
                    "31612345678",
                    "12561234567",
                    "441234567890"
                ]
            },
            "push": {
                "enabled": true,
                "config": {
                    "post_url": "https://api.pushover.net/1/messages.json"
                },
                "subscribers_tokens": [
                    ["<pushover API TOKEN>", "<pushover USER TOKEN>"],
                    ["<pushover API TOKEN>", "<pushover USER TOKEN>"]
                ]
            },
            "hosts": [
                {
                    "reliable": true,
                    "host": "https://google.com"
                },
                {
                    "host": "ping://host-to-be-checked-with-ping.com"
                },
                {
                    "host": "ping://123.45.67.89"
                },
                {
                    "host": "http://host-to-be-checked-with-http-call.com"
                },
                {
                    "host": "https://host-to-be-checked-with-https-call.com"
                },
                {
                    "host": "https://another-host.com/with/specific/url/"
                },
                {
                    "host": "dns://host-to-be-checked-via-dns.com"
                },
                {
                    "host": "dnstcp://host-to-be-checked-via-dns-using-tcp.com"
                },
                {
                    "host": "dnsdig://host-to-be-checked-with-dig-call.com",
                    "name_servers": [
                        "expected-nameserver1.some-provider.com",
                        "expected-nameserver2.some-provider.com",
                        "expected-nameserver3.some-provider.com"
                    ]
                },
                {
                    "host": "https://epp.whois.ai"
                },
                {
                    "notify_once": true,
                    "host": "http://only-one-notification-will-be-sent.com"
                },
                {
                    "notify_once": false,
                    "host": "http://notifications-will-continue-untill-host-is-alive-again.com"
                }
            ]
        }



## manual execution

To test the script you can execute it directly from command line:

        cd simple-healthcheck
        python3 simple_healthcheck.py -c config.json -t history.txt -v



## setup a periodic CRON task

The `simple-healthcheck` script is meant to be executed directly with CRON task.

For example, to run `simple-healthcheck` every 15 minutes, you can do such:

        crontab -e

        */15 * * * * python3 /home/user/simple-healthcheck/simple_healthcheck.py -v -c /home/user/simple-healthcheck/config.json -t /home/user/simple-healthcheck/history.txt 1>>/tmp/simple-healthcheck.log 2>>/tmp/simple-healthcheck.err
