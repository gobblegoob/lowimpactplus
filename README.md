# lowimpactplus
Python 3.7

Takes raw report output from ISE RADIUS authentication logs and outputs a csv file of devices that are still hitting your low impact/monitor mode policies.

You will need to modify the following:
1. Global Variable: src_report
  This defines your source csv you wish to parse.
  
2. li[] in get_low_impact()
  This is an array of low impact policies you wish to search on. Just enter values that match your low impact/monitor mode policies.
  

DEPENDENCIES:
  Pandas
   
