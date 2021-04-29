"""SilverLine Denylist Management.

This module contains functions to view, add or delete IP Address
from SilverLine Denylist.
"""

import requests
import os
import yaml
from helper_fts.email import send_email
from helper_fts.splunk import splunk_log_event
from helper_fts.fts_sane import *

requests.packages.urllib3.disable_warnings()


def get_denylist(url, token, verify_ssl=False):
    """Get Tenant specific denylist.

    Args:
        url (str): SilverLine Portal URL
        token (str): SilverLine Tenant specific Token

    Returns:
        Requests response object.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Authorization-Token": token,
        "cache-control": "no-cache",
    }
    resp = requests.get(url=f"{url}ip_lists/denylist/ip_objects", verify=verify_ssl, headers=headers)
    return resp.json()


def add_ip2denylist(url, token, addr, mask, verify_ssl=False):
    """Add new IPv4 address to Tenant specific denylist.

    Args:
        url (str): SilverLine Portal URL
        token (str): SilverLine Tenant specific Token
        addr (str): IPv4 Address
        mask (str): IPv4 network mask

    Returns:
        int : Requests response status_code
    """
    headers = {
        "Content-Type": "application/json",
        "X-Authorization-Token": token,
        "cache-control": "no-cache",
    }
    payload = {"data": {"type": "ip_objects", "attributes": {"duration": 0}}}
    payload["data"]["id"] = addr + "_" + mask
    payload["data"]["attributes"]["ip"] = addr
    payload["data"]["attributes"]["mask"] = mask

    resp = requests.post(
        url=f"{url}ip_lists/denylist/ip_objects?list_target=routed", verify=verify_ssl, headers=headers, json=payload
    )
    return resp.status_code


def delete_ipfromdenylist(url, token, id, verify_ssl=False):
    """Delete IPv4 address to Tenant specific denylist.

    Args:
        url (str): SilverLine Portal URL
        token (str): SilverLine Tenant specific Token
        id (str): ID of ip_object which need to be deleted

    Returns:
        int : Requests response status_code
    """
    headers = {
        "Content-Type": "application/json",
        "X-Authorization-Token": token,
        "cache-control": "no-cache",
    }
    resp = requests.delete(
        url=f"{url}ip_lists/denylist/ip_objects/{id}?list_target=routed", verify=verify_ssl, headers=headers
    )
    return resp.status_code


def view_aciton(url, token):
    """View data function.

    Args:
        url (str): SilverLine Portal URL
        token (str): SilverLine Tenant specific Token
    """
    deny_list = []
    data = get_denylist(url, token)
    for i in data["data"]:
        if "routed" in i["attributes"]["list_target"]:
            deny_list.append(
                # {"id": i["id"], "ip": i["attributes"]["ip"], "mask": i["attributes"]["mask"], "note": i["meta"]["note"]}
                {"id": i["id"], "ip": i["attributes"]["ip"], "mask": i["attributes"]["mask"]}
            )
    return deny_list


if __name__ == "__main__":

    """
    This main function will receive 3 arguments
    (token, action, address) which are passed from Rundeck workflow

    """

    url = "https://portal.f5silverline.com/api/v1/"
    tenant_lst = []
    # tenant_lst.append({"name": "Fiserv-Development (firstdata7)", "token": str(sys.argv[1])})
    tenant_lst.append({"name": "Fiserv-Development (firstdata7)", "token": os.environ.get("RD_OPTION_TOKEN")})
    # token = str(sys.argv[1])

    # Opening JSON file
    f = open("data/deny_list.yml")

    # returns JSON object as  a dictionary
    intend_data = yaml.safe_load(f)

    msg_data = []
    # Iterating through the json list to Add new Address or to update comments
    for tenant in tenant_lst:
        current_data = view_aciton(url, tenant["token"])
        for idata in intend_data["deny_list"]:
            add1 = True
            for cdata in current_data:
                if (idata["addr"].split("/")[0] == cdata["ip"]) and (idata["addr"].split("/")[1] == cdata["mask"]):
                    add1 = False

            if add1:
                addr = idata["addr"].split("/")[0]
                mask = idata["addr"].split("/")[1]
                resp = add_ip2denylist(url, tenant["token"], addr, mask, verify_ssl=False)
                if resp == 201:
                    msg_data.append(f"{tenant['name']} : Successfully added {idata['addr']}")
                else:
                    msg_data.append(f"{tenant['name']} : ERROR - Couldn't added {idata['addr']}")
                    msg_data.append(f"{tenant['name']} : Response Code {resp}")

        # Iterating through the json list to Delete Address
        for cdata in current_data:
            del1 = True
            for idata in intend_data["deny_list"]:
                if (cdata["ip"] == idata["addr"].split("/")[0]) and (cdata["mask"] == idata["addr"].split("/")[1]):
                    del1 = False
            if del1:
                resp = delete_ipfromdenylist(url, tenant["token"], cdata["id"], verify_ssl=False)
                if resp == 200:
                    msg_data.append(f"{tenant['name']} : Successfully removed {cdata['ip']}/{cdata['mask']}")
                else:
                    msg_data.append(f"{tenant['name']} : ERROR - Couldn't remove {cdata['ip']}/{cdata['mask']}")
                    msg_data.append(f"{tenant['name']} : Response Code {resp}")

    for pdata in msg_data:
        print(f"\t{pdata}")

    d = {
        "From": "sane_automation@fiserv.com",
        "to": "paul.thomas@Fiserv.com, Andy.Clark@Fiserv.com, william.dolbow@Fiserv.com",
        "cc": "harish.krishnoji@Fiserv.com",
        "subject": "F5 SliverLine DenyList - Routed Mode ONLY",
        "body": msg_data,
    }
    send_email(**d)
    # SPLUNK_VAR["token"] = f"Splunk {str(sys.argv[2])}"
    SPLUNK_VAR["token"] = f"Splunk {os.environ.get('RD_OPTION_SPLUNKTOKEN')}"
    SPLUNK_VAR["data"] = msg_data
    splunk_log_event(**SPLUNK_VAR)

    # Closing file
    f.close()
