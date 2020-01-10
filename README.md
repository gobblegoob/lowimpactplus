# lowimpactplus
Python 3.7

Cisco ISE is terrible at giving you accurate reports of endpoints that are hitting your low impact/monitor mode policies.  Identifying and remediating these endpoints is crucial to moving your network to full enforcement.  

This script takes raw report output from ISE RADIUS authentication logs and outputs a csv file of devices that are still hitting your low impact/monitor mode policies.  It is recommended that you take a 30 day authentication report with no filters.

You will need to modify the following:
1. Global Variable: src_report
  This defines your source csv you wish to parse.
  
2. li[] in get_low_impact()
  This is a list of low impact policies you wish to search on. Just enter values that match your low impact/monitor mode policies.  This is a list in case you have multiple low impact policies you wish to watch.
  

DEPENDENCIES:
  Pandas
   
