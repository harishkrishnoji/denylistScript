"""SilverLine Denylist Management.

This module contains Helper functions.
"""

import requests

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
