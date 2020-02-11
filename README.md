# lowimpactplus
Python 3.7

Cisco ISE is terrible at giving you accurate reports of endpoints that are hitting your low impact/monitor mode policies.  Identifying and remediating these endpoints is crucial to moving your network to full enforcement.  

This script takes raw report output from ISE RADIUS authentication logs and outputs a csv file of devices that are still hitting your low impact/monitor mode policies, eliminating duplicates and false positives (such as a low impact rule being hit during a reboot before the 802.1x supplicant on an endpoint can load).  It is recommended that you take a 30 day authentication report with no filters.

You will need to modify the following:
1. Global Variable: src_report
  This defines your source csv you wish to parse.
  
2. Global Variable: li_policy_list: 
  This is a list of all Low Impact/Monitor Mode policies that you are watching. 

DEPENDENCIES:
  Pandas
   
