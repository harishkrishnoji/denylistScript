"""SilverLine Denylist Management.

This module contains functions to view, add or delete IP Address
from SilverLine Denylist.
"""

import os
import yaml
from helper_fts.email import send_email
from helper_fts.splunk import splunk_log_event
from helper_fts.fts_sane import *
from helperfun import *

if __name__ == "__main__":

    """
    This is main function.

    """

    url = "https://portal.f5silverline.com/api/v1/"
    tenant_lst = []
    tenant_lst.append(
        {"name": "Fiserv-Development (firstdata7)", "token": os.environ.get("RD_OPTION_TOKEN_ALL").split(",")[0]}
    )
    # tenant_lst.append(
    #     {"name": "Fiserv-Clover (firstdatac6)", "token": os.environ.get("RD_OPTION_TOKEN_ALL").split(",")[1]}
    # )
    # tenant_lst.append(
    #     {"name": "Fiserv-OFS (firstdatac5)", "token": os.environ.get("RD_OPTION_TOKEN_ALL").split(",")[2]}
    # )
    # tenant_lst.append(
    #     {"name": "First Data Corporation (firstdata)", "token": os.environ.get("RD_OPTION_TOKEN_ALL").split(",")[3]}
    # )

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
    SPLUNK_VAR["token"] = f"Splunk {os.environ.get('RD_OPTION_SPLUNKTOKEN')}"
    SPLUNK_VAR["data"] = msg_data
    splunk_log_event(**SPLUNK_VAR)

    # Closing file
    f.close()
