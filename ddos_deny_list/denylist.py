"""SilverLine Denylist Management.

This module contains functions to view, add or delete IP Address
from SilverLine Denylist.
"""

import requests
import sys
import time
import yaml

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

    resp = requests.post(url=f"{url}ip_lists/denylist/ip_objects", verify=verify_ssl, headers=headers, json=payload)
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
    resp = requests.delete(url=f"{url}ip_lists/denylist/ip_objects/" + id, verify=verify_ssl, headers=headers)
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
                {"id": i["id"], "ip": i["attributes"]["ip"], "mask": i["attributes"]["mask"], "note": i["meta"]["note"]}
            )
    return deny_list


if __name__ == "__main__":

    """
    This main function will receive 3 arguments
    (token, action, address) which are passed from Rundeck workflow

    """

    url = "https://portal.f5silverline.com/api/v1/"
    token = str(sys.argv[1])

    # Opening JSON file
    f = open("data/deny_list.yml",)

    # returns JSON object as  a dictionary
    intend_data = yaml.safe_load(f)
    current_data = view_aciton(url, token)

    # Iterating through the json list to Add new Address or to update comments
    for idata in intend_data["deny_list"]:
        add1 = True
        for cdata in current_data:
            if (idata["addr"].split("/")[0] == cdata["ip"]) and (idata["addr"].split("/")[1] == cdata["mask"]):
                add1 = False

        if add1:
            addr = idata["addr"].split("/")[0]
            mask = idata["addr"].split("/")[1]
            resp = add_ip2denylist(url, token, addr, mask, verify_ssl=False)
            if resp == 201:
                print(f"\tSuccessfully added {idata} to the Deny-list")
            else:
                print(f"\tERROR : Couldn't added {idata} to the Deny-list")
                print(f"\tResponse Code : {resp}")

    # Iterating through the json list to Delete Address
    for cdata in current_data:
        del1 = True
        for idata in intend_data["deny_list"]:
            if (cdata["ip"] == idata["addr"].split("/")[0]) and (cdata["mask"] == idata["addr"].split("/")[1]):
                del1 = False
        if del1:
            resp = delete_ipfromdenylist(url, token, cdata["id"], verify_ssl=False)
            if resp == 200:
                print(f"\tSuccessfully removed {cdata} from Deny-list")
            else:
                print(f"\tERROR : Couldn't remove {cdata} from Deny-list")
                print(f"\tResponse Code : {resp}")

    # Wait for 60 sec to pull modified data
    time.sleep(60)
    data = view_aciton(url, token)
    print("\n\tCurrent Denylist")
    for lst in data:
        print(f"\t{lst}")

    # Closing file
    f.close()
