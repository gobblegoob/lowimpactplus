###############################################################
#   Get RADIUS Authentication report From ISE for
#   some length of time.
#
#   Will parse this information to identify which devices are still
#   hitting a Low Impact/Monitor mode policy so they
#   can be remediated.
#
#   You can customize your low impact policies you want to search for
#   by modifying the li[] list in get_low_impact()
#
#   Takes raw output from the RADIUS Authentications reports
#   including all authentications.  No filters.
#
#   -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-
#   Author: Garrett Munson
#   8/19/2019
###############################################################

import csv
import numpy
import pandas as pd
import datetime
import os

src_report = 'AAA/RptExp_presidio_30_Days_-_RADIUS_Authentications_2019-08-29_18-59-00.000000096(1).csv'
src_dc_auth_count = 0
mab_ep = []
d1x_ep = []
csv_header = ''
output_csv = []  # Array that creates the output file


def initialize():
    global src_report
    print('\n' * 10)
    print('~' * 20 + 'Low Impact Report' + '~' * 10)
    freport = filter_report(src_report)
    m = get_low_impact(freport)
    d = get_authenticated(freport)

    l = create_auth_list(m)
    a = create_auth_list(d)

    compare_auths(l, a)
    print_output_file(output_csv)
    remove_file(m)
    remove_file(d)
    return


def filter_report(file):
    try:
        df = pd.read_csv(file)
        # Pull the relevant fields
        filtered_report = df[['\'CALLING_STATION_ID\'',
                                '\'LOCATION\'',
                                '\'LOGGED AT\'',
                                '\'POLICY_SET_NAME\'',
                                '\'ENDPOINTMATCHEDPROFILE\'',
                                '\'IDENTITY_GROUP\'',
                                '\'NAS_IP_ADDRESS\'',
                                '\'NETWORK_DEVICE_NAME\'',
                                '\'NAS_PORT_ID\'',
                                '\'USER_NAME\'',
                                '\'AUTHORIZATION_RULE\'']]
        header = ',Calling Station ID,' \
                 'Location,Logged At,' \
                 'Policy Set,' \
                 'Endpoint Profile,' \
                 'Identity Group,'\
                 'NAS IP Address,'\
                 'Network Device Name,'\
                 'Port ID,'\
                 'User Name,'\
                 'Authorization Rule\n'
        create_csv_header(header)
        # print(filtered_report.loc[1)
        return filtered_report
    except KeyError:
        filter_report_pe(file)
        return
    except FileNotFoundError:
        print(FileNotFoundError)
        return

def filter_report_poe(file):
    try:
        df = pd.read_csv(file)
        # Pull the relevant fields
        filtered_report = df[['\'CALLING_STATION_ID\'',
                              '\'LOCATION\'',
                              '\'LOGGED AT\'',
                              '\'POLICY_SET_NAME\'',
                              '\'ENDPOINTMATCHEDPROFILE\'',
                              '\'IDENTITY_GROUP\'',
                              '\'NAS_IP_ADDRESS\'',
                              '\'NETWORK_DEVICE_NAME\'',
                              '\'NAS_PORT_ID\'',
                              '\'USER_NAME\'',
                              '\'AUTHORIZATION_RULE\'']]
        header = ',Calling Station ID,' \
                 'Location,Logged At,' \
                 'Policy Set,' \
                 'Endpoint Profile,' \
                 'Identity Group,' \
                 'NAS IP Address,' \
                 'Network Device Name,' \
                 'Port ID,' \
                 'User Name,' \
                 'Authorization Rule\n'
        create_csv_header(header)
        # print(filtered_report.loc[1)
        return filtered_report
    except KeyError:
        print('Unable to read source CSV Keys')
        print(KeyError)
        return

def get_low_impact(df):
    li = ['\'Low_Impact_All_Sites\'', '\'Low_Impact_Call_Centers\'', '\'Low_Impact_Florida_Branches\'']
    try:
        # Isolate the low impact authentications
        print('Finding Low Impact Authorizations ...')
        li_df = df.loc[df['\'AUTHORIZATION_RULE\''].isin(li)]
        fn = get_date() + 'LowImpact.csv'
        # deduplicate the dataframe
        li_df = li_df.drop_duplicates(subset='\'CALLING_STATION_ID\'', keep='first')
        # Create formatted and deduped csv file
        li_df.to_csv(fn)

        return fn
    except KeyError:
        get_low_impact_pe(file)
    except FileNotFoundError:
        print('get_low_impact(): File Not Found')
        quit()


def get_authenticated(df):
    global src_dc_auth_count
    li = ['\'Low_Impact_All_Sites\'', '\'Low_Impact_Call_Centers\'', '\'Low_Impact_Florida_Branches\'']
    try:
        print('Finding Authenticated Devices ...')
        a_df = df.loc[~df['\'AUTHORIZATION_RULE\''].isin(li)]
        a_df = a_df.drop_duplicates(subset='\'CALLING_STATION_ID\'', keep='first')

        # Set the count of authenticated endpoints
        src_dc_auth_count = a_df.shape[0]

        fn = get_date() + 'authenticated.csv'
        # print(a_df.loc[1])
        a_df.to_csv(fn)

        return fn
    except KeyError:
        print('Authenticated df key error. Handle me')
    except FileNotFoundError:
        print('Source file not found')
        quit()


def create_auth_list(src_file):
    try:
        with open(src_file) as sfile:
            readfile = csv.reader(sfile, delimiter=',')
            next(readfile)
            endpoints = []
            for row in readfile:
                endpoints.append(row)
            return endpoints
    except:
        print("Unknown Error - create_auth_list()")


def compare_auths(mab, d1x):
    count = 1
    global output_csv
    global src_dc_auth_count
    test = []
    try:
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
                # print(count)
            count = 1
        return
    except FileNotFoundError:
        print(mab + ' is not found')
        raise



def print_output_file(le):
    global csv_header

    fname = get_date() + 'LowImpactReport.csv'
    print('#' * 50)
    print('Creating Output File: ' + fname + '...')
    headers = csv_header

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

    print('\nCompleted Report!' + '\n' * 10)
    return

def get_date():
    now = datetime.datetime.now()
    year = now.year
    month = now.month
    day = now.day

    y = str(year)
    m = str(month)
    d = str(day)

    d = y + '_' + m + '_' + d + '_'

    return d


def create_csv_header(header):
    global csv_header
    csv_header = header
    return


def remove_file(fname):
    try:
        os.remove(fname)
    except Exception:
        pass


if __name__ == '__main__':
    try:
        initialize()
    except KeyboardInterrupt:
        print('You have cancelled the operation')
        print('\n' * 10)
