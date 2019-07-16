###############################################################
#   takes 2 source csv files and merges them
#   while removing duplicates.
#
#   Requires output from low impact/monitor mode authentications
#   and another file with dot1x authentications
#
#   The goal is to find endpoints that are hitting low impact
#   and have not since authenticated with 802.1x
#   Output is a list of MABbed devices that have not authenticated
#   with 802.1x
#   -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-
#   Author: Garrett Munson
#   7/11/2019
###############################################################

import csv
import numpy
import pandas as pd
import os
import datetime

src_domain = 'dom.csv'
src_lowimpact = 'low.csv'
src_dc_auth_count = 0
mab_ep = []
d1x_ep = []
output_csv = []
formatted_domain_file = 'domain_formatted.csv'
formatted_low_file = 'lowimpact_formatted.csv'


def initialize():
    global src_lowimpact
    global src_domain
    global mab_ep
    global d1x_ep
    global formatted_domain_file
    global formatted_low_file

    dom = format_report(src_domain)
    low = format_report(src_lowimpact)

    domf = create_report_file(dom, formatted_domain_file)
    lowf = create_report_file(low, formatted_low_file)
    ###############################################
    # UPDATE THIS TO TAKE THE FORMATTED SOURCE FILE
    count_dot1x_auths(domf)
    mab_ep = get_mab_auth(lowf)
    d1x_ep = get_dot1x_auth(domf)
    ###############################################
    compare_auths(mab_ep, d1x_ep)
    print_output_file(output_csv)


def format_report(file):
    df = pd.read_csv(file)
    # Sort on MAC address
    rep_sort = df.sort_values('\'CALLING_STATION_ID\'', ascending=False)
    # Pull relevant fields
    dom_report = rep_sort[[ '\'CALLING_STATION_ID\'', '\'LOCATION\'', '\'LOGGED AT\'',  '\'POLICY_SET_NAME\'', '\'ENDPOINTMATCHEDPROFILE\'', '\'IDENTITY_GROUP\'', '\'NAS_IP_ADDRESS\'', '\'NETWORK_DEVICE_NAME\'', '\'NAS_PORT_ID\'', '\'USER_NAME\'', '\'AUTHORIZATION_RULE\'']]
    # Deduplicate MAC addresses
    rep_final = dom_report.drop_duplicates(subset='\'CALLING_STATION_ID\'', keep='first')
    return rep_final


def create_report_file(report_object, fname):
    remove_file(fname)
    try:
        report_object.to_csv(path_or_buf=fname)
        return fname
    except Exception:
        print('Could not create file')


def remove_file(fname):
    try:
        os.remove(fname)
    except Exception:
        pass


def count_dot1x_auths(src_dc):
    global src_dc_auth_count
    with open(src_dc) as dot1xfile:
        readfile = csv.reader(dot1xfile, delimiter=',')
        next(dot1xfile)
        for row in readfile:
            src_dc_auth_count += 1
    print('Rows in source file: ', src_dc_auth_count)
    return


def get_mab_auth(src_li):
    try:
        with open(src_li) as mabfile:
            readfile = csv.reader(mabfile, delimiter=',')
            next(readfile)
            endpoints = []
            for row in readfile:
                endpoints.append(row)
            return endpoints
    except:
        print("Unknown error")


def get_dot1x_auth(src_dx):
    try:
        with open(src_dx) as dot1xfile:
            readfile = csv.reader(dot1xfile, delimiter=',')
            next(readfile)
            endpoints = []
            for row in readfile:
                endpoints.append(row)
            return endpoints
    except Exception:
        print("Broke at get_dot1x_auth()")


def compare_auths(mab, d1x):
    count = 1
    global output_csv
    global src_dc_auth_count
    test = []
    for m in mab:
        for d in d1x:
            if m[1] != d[1] and count >= src_dc_auth_count:
                test.append(m)
                output_csv.append(m)
                count = 1
                continue
            elif m[1] == d[1] and count < src_dc_auth_count:
                count = 1
                continue
            elif m[1] != d[1] and count < src_dc_auth_count:
                count += 1
        count = 1
    return


def get_date():
    now = datetime.datetime.now()
    year = now.year
    month = now.month
    day = now.day

    y = str(year)
    m = str(month)
    d = str(day)

    d = y + '_'+ m +'_' + d + '_'

    return d


def print_output_file(le):
    global formatted_domain_file
    global formatted_low_file

    fname = get_date() + 'LowImpactReport.csv'
    print('Creating Output File: ' + fname + '...')
    headers = ',MAC Address,Location,LOGGED AT,Policy Set Endpoint Profile,Name,ID Group,Switch IP Address,Switch Name,Switch Port,Username,Authorization Rule\n'

    global output_csv

    f = open(fname, 'w+')
    f.write(headers)
    f.close()
    f =open(fname, 'a+')
    for i in output_csv:
        str_i = str(i)
        f.write(str_i)
        f.write('\n')
        # print(i)
    f.close()
    os.remove(formatted_low_file)
    os.remove(formatted_domain_file)
    return


if __name__ == '__main__':
    try:
        initialize()
    except KeyboardInterrupt:
        print('You have cancelled the operation')