###############################################################
#   Get RADIUS Authentication report From ISE for
#   some length of time.
#
#   Will parse this information to identify which devices are still
#   hitting a Low Impact/Monitor mode policy so they
#   can be remediated.
#
#   You can customize your low impact policies you want to search for
#   by modifying global list li_policy_list with the full names
#   of your Low Impact policies.
#                                                                                                                                                                                                                                                                                                                                          
#   Takes raw output from the RADIUS Authentications reports
#   including all authentications.  No filters.
#
#   -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-
#   Author: Garrett Munson
#   8/19/2019
###############################################################

import csv
import pandas as pd
import datetime
import os
import argparse
import os

src_report = ''
src_dc_auth_count = 0  # Count of authenticated endpoints.
mab_ep = []
d1x_ep = []
csv_header = ''
output_csv = []  # Array that creates the output file

# li_policy_list is a list of your low impact policies you wish to search against
# Devices hitting these policies likely need to be remediated
# Each li_policy_list value should match an AUTHORIZATION_RULE in the RADIUS report
# Delete the following values and add your own
li_policy_list = [
                  'Low Impact'
                 ]

def filter_report(df):
    """
    Filters out the necessary fields of the low impact report and exports it
    to a Pandas dataframe

    :param file: Pandas DataFrame
    :return: filtered_report - Pandas DataFrame
    """
    try:
        # Pull the relevant fields
        filtered_report = df[['CALLING_STATION_ID',
                                'LOCATION',
                                'ACSVIEW_TIMESTAMP',
                                'POLICY_SET_NAME',
                                'ENDPOINTMATCHEDPROFILE',
                                'IDENTITY_GROUP',
                                'NAS_IP_ADDRESS',
                                'NETWORK_DEVICE_NAME',
                                'NAS_PORT_ID',
                                'USER_NAME',
                                'AUTHORIZATION_RULE']]
        header = ',Calling Station ID,' \
                 'Location,' \
                 'Logged Time,' \
                 'Policy Set,' \
                 'Endpoint Profile,' \
                 'Identity Group,'\
                 'NAS IP Address,'\
                 'Network Device Name,'\
                 'Port ID,'\
                 'User Name,'\
                 'Authorization Rule\n'
        create_csv_header(header)
        return filtered_report
    except KeyError:
        sr_filtered_report = filter_short_report(df)
        return sr_filtered_report

    except FileNotFoundError:
        print('Source file not found: ' + src_report)
        quit()
    
    except TypeError as e:
        print(f'Type error in filter_report()\n{e}')
        quit()


def filter_short_report(df):
    """
    Filtered non-30 day reports export with different headers.  This function will allow the application
    to ingest and analyze these types of reports.

    :param file: Pandas DataFrame
    :return: filtered_report Pandas Dataframe
    """
    try:
        # Pull the relevant fields
        filtered_report = df[['Endpoint ID',
                                'Location',
                                'Logged At',
                                'Endpoint Profile',
                                'Identity',
                                'Network Device IP',
                                'Network Device',
                                'Device Port',
                                'Identity',
                                'Authorization Rule']]
        header = ',Calling Station ID,' \
                 'Location,Logged At,' \
                 'Endpoint Profile,' \
                 'Identity Group,'\
                 'NAS IP Address,'\
                 'Network Device Name,'\
                 'Port ID,'\
                 'User Name,'\
                 'Authorization Rule\n'
        create_csv_header(header)
        return filtered_report
    except KeyError:
        print('File headers incorrect\n'
              'Please fix or obtain a new report')
        quit()
        return
    except FileNotFoundError:
        print('Source file not found: ' + src_report)
        quit()
        return

def get_low_impact(df):
    """
    Update this Array with the Authorization Policies you want to check
    It must be a full match!  Add or remove as needed

    :param df: pandas dataframe, returned from filtered_report()
    :return: fn - Output filename.
    """
    global li_policy_list
    li = li_policy_list
    try:
        # Isolate the low impact authentications
        print('Finding Low Impact Authorizations ...')
        li_df = df.loc[df['AUTHORIZATION_RULE'].isin(li)]
        fn = get_date() + 'LowImpact.csv'
        # deduplicate the dataframe
        li_df = li_df.drop_duplicates(subset='CALLING_STATION_ID', keep='first')
        # Create formatted and deduped csv file
        li_df.to_csv(fn)

        # Testing - print number of hits
        print('Low Impact count should match kill count to indicate no unsuccessful authentications found.')
        print(len(li_df.index))
        return fn
    except KeyError:
        print('Key error: get_low_impact()')
        fn_sr = get_low_impact_short_report(df)
        return fn_sr
        quit()
    except FileNotFoundError:
        print('get_low_impact(): File Not Found')
        quit()


def get_low_impact_short_report(df):
    """
    Short report. Uses short report headers.

    :param df: pandas dataframe, returned from filtered_report()
    :return: fn - Output filename.
    """
    global li_policy_list
    li = li_policy_list
    try:
        # Isolate the low impact authentications
        print('Finding Low Impact Authorizations ...')
        li_df = df.loc[df['Authorization Rule'].isin(li)]
        fn = get_date() + 'LowImpact.csv'
        # deduplicate the dataframe
        li_df = li_df.drop_duplicates(subset='Endpoint ID', keep='first')
        # Create formatted and deduped csv file
        li_df.to_csv(fn)

        # Testing - print number of hits
        print('Low Impact count should match kill count to indicate no unsuccessful authentications found.')
        print(len(li_df.index))
        return fn
    except KeyError:
        print('Key error: get_low_impact_short_report()')
        quit()
    except FileNotFoundError:
        print('get_low_impact(): File Not Found')
        quit()


def get_authenticated(df):
    """
    Get Authentications to be compared

    :param df: Pandas Dataframe
    :return: Filename
    """
    global src_dc_auth_count
    global li_policy_list
    li = li_policy_list
    try:
        print('Finding Authenticated Devices ...')
        a_df = df.loc[~df['AUTHORIZATION_RULE'].isin(li)]
        a_df = a_df.drop_duplicates(subset='CALLING_STATION_ID', keep='first')

        # Set the count of authenticated endpoints
        src_dc_auth_count = len(a_df.index)

        fn = get_date() + 'authenticated.csv'
        # print(a_df.loc[1])
        a_df.to_csv(fn)

        return fn
    except KeyError:
        fn = get_authenticated_short_report(df)
        return fn
        quit()
    except FileNotFoundError:
        print('Source file not found')
        quit()


def get_authenticated_short_report(df):
    """
    Uses Short Report Headers

    :param df: Pandas Dataframe
    :return: fn - Filename for csv of authentications
    """
    global src_dc_auth_count
    global li_policy_list
    li = li_policy_list
    try:
        print('Finding Authenticated Devices ...')
        a_df = df.loc[~df['Authorization Rule'].isin(li)]
        a_df = a_df.drop_duplicates(subset='Endpoint ID', keep='first')

        # Set the count of authenticated endpoints
        src_dc_auth_count = len(a_df.index)

        fn = get_date() + 'authenticated.csv'
        # print(a_df.loc[1])
        a_df.to_csv(fn)

        return fn
    except KeyError:
        print('Authenticated df key error. Handle me')
        quit()
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
        quit()


def compare_auths(mab, d1x):
    """
    Compares Low Impact authentications
    :param mab: temp file that tracks low impact authentications
    :param d1x: temp file that tracks endpoints that hit intended authorization policies
    :return: Nothing
    """
    count = 1
    global output_csv
    global src_dc_auth_count
    killcount = 0
    try:
        for m in mab:
            for d in d1x:
                # upper constraint.  m matched no d
                # and the end of the file was reached, so append to list
                # the count is reset to 1 and a new m is compared
                if m[1] != d[1] and count >= src_dc_auth_count:
                    output_csv.append(m)
                    # print(m)
                    count = 1
                    continue
                # we found a match.  reset count to 1 to compare
                # a new m and continue
                elif m[1] == d[1] and count < src_dc_auth_count:
                    count = 1
                    killcount += 1
                    continue
                # m does not match d, keep looking
                elif m[1] != d[1] and count < src_dc_auth_count:
                    count += 1
            #    print(count)
            count = 1
        kc = str(killcount)
        print('Kill count = ' + kc)
        return
    except FileNotFoundError:
        print(mab + ' is not found')
        quit()


def create_report_df(report_list):
    '''
    Take the output_csv report and create a pandas dataframe.
    This is a dataframe of the completed report with added columns for 
    endpoint information and remediation plans
    :arg: list of completed report
    :return: Pandas Dataframe containing completed report with added columns
    '''
    col_list = [
        'num',
        'Calling Station ID',
        'Location',
        'Logged Time',
        'Policy Set',
        'Endpoint Profile',
        'Identity Group',
        'NAS IP Address',
        'Network Device Name',
        'Port ID',
        'User Name',
        'Authorization Rule'
    ]
    report_df = pd.DataFrame(report_list, columns=col_list)
    list = report_list[0]
    report_df.loc[len(report_df)] = list
    report_df = report_df.drop('num', axis=1)

    dummy_value = []
    i= 0
    while i < report_list.__len__():
        i+=1
        dummy_value.append('')
    
    dummy_value.append('')

    # Insert the new columns
    #Empty columm for Endpoint Type
    report_df.insert(loc=2, column='Endpoint Type', value=dummy_value)
    # Empty column for Authentication Plan
    report_df.insert(loc=3, column='Authentication Plan', value=dummy_value)
    # Empty column for Remeidation status
    report_df.insert(loc=4, column='Remediation Status', value=dummy_value)
    return report_df


def output_excel_report(report_df):
    '''
    Create a nice low impact report
    :arg: Pandas dataframe
    :return:
    '''
    fname = get_date() + 'LowImpactReport.xlsx'
    try:
        if report_df.to_excel(fname, index=False) == True:
            return True
    except Exception as e:
        print(f'Error creating report {fname}\n{e}')
        return False


def print_output_file(le):
    """
    Creates the final Low Impact Report .csv file

    :param le: List that contains all endpoints that need remediation.
    :return: Nothing
    """
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
        str_i = str_i[1:-1]
        str_i = str_i.replace('\'', '')
        str_i = str_i.replace('\"', '')
        # print(str_i)
        f.write(str_i)
        f.write('\n')
        # print(i)
    f.close()

    print('\nCompleted Report!' + '\n' * 2)
    return fname


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


def multifile_dataframe(source):
    '''
    If RADIUS report comes in a directory containing multiple files, we must concatinate the csv files
    into a single pandas dataframe for operations.
    The number of records can get too high to operate on within excel or a text editor otherwise.
    :arg: str
    :return: Dataframe (merged)
    '''
    #Get file list in folder
    f_list = os.listdir(source)
    # Need them in order so the newest authentications are tracked accurately.
    # ISE exports files in order of most recent to oldest
    f_list.sort()
    #change directory
    os.chdir(source)
    try:
        for f in f_list:
            if f_list[0] == f:
                my_df = pd.read_csv(f)
            else:
                print(f'Looking to merge file {f} to dataframe...')
                append_df = pd.read_csv(f)
                my_df = pd.concat([my_df, append_df], ignore_index=True)
                print(f'Merge completed:\n Headers: {my_df.head}\n Shape: {my_df.shape}')

        return my_df
    except Exception as e:
        print(f'Error in multifile_dataframe\n{e}')
        print(f'file: {f}')
        quit()

    


def find_source(source):
    '''
    Is the source a file or directory?  Start correcto operation accordingly
    :arg: str
    :return: not sure yet.
    '''
    try:
        if os.path.isfile(source) == True:
            global src_report
            src_report = source
            my_df = pd.read_csv(source)
            return my_df
        elif os.path.isdir(source) == True:
            my_df = multifile_dataframe(source)
            return my_df
        else:
            print(f'Source error {source} is not a file or directory')
            quit()
    except Exception as e:
        print(f'Error in find_source.\n {e}')
        quit()


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(
            prog='LowImpactPlus',
            description='Crunch ISE RADIUS Logs, deduplicate and identify endpoints by authorization profile'
        )
        #Arguments
        parser.add_argument('-s', '--source', type=str, required=False, help='Designate a source file or directory')

        args = parser.parse_args()

        if args.source != None:
            df = find_source(args.source)
        else:
            try:
                df = pd.read_csv(src_report)
            except FileNotFoundError as e:
                print(e)
                quit()


        print('\n' * 2)
        print('~' * 20 + 'Low Impact Report' + '~' * 20)
        freport = filter_report(df)
        m = get_low_impact(freport)
        d = get_authenticated(freport)

        l = create_auth_list(m)
        a = create_auth_list(d)

        compare_auths(l, a)
        #report_csv = print_output_file(output_csv)

        # Create completed report dataframe
        report_df = create_report_df(output_csv)

        # Convert dataframe to formatted XLSX
        output_excel_report(report_df)

        # cleanup
        remove_file(m)
        remove_file(d)
    except KeyboardInterrupt:
        print('You have cancelled the operation')
        print('\n' * 10)
