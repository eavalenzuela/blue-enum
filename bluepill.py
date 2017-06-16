import re, sys, os
#import argparse
import ipaddress
from subprocess import Popen, PIPE
import xml.etree.ElementTree

#
#	bluepill.py
#		a custom scanning script I built for the OSCP
#
#	Eric Valenzuela, eevn.io
#	June 14, 2017
#

#parser = argparse.ArgumentParser(description='BluePill scanner')
#parser.add_argument('ip', type=str, help='an ip address or CIDR block to scan, e.g. "192.168.0.1", "192.168.0.0/24"')
#args = parser.parse_args()

##### Main Menu funtion --start--
def menu (mitem):
    print ('\n\nBluepill scanner.\nPlease make a selection.\n   1: Add IPs\n   2: Run Scans\n   3: Clear IPs\n   4: Program select\n   5: List IPs\n   6: Rebuild IP list from files\n   7: Utilities\n   8: Exit')
    try:
        while mitem == None:
            try:
                mitem = input('bp_$>')
            except SyntaxError:
                mitem = None
    except NameError:
        print("You have entered an invalid name.\n")
    return mitem
##### Main Menu function --end--

##### Program Menu function --start--
def progmenu(mitem):
    return mitem
##### Program Menu function --end--

##### Utility Menu function --start--
def utilmenu(addr):
    uitem = None
    try:
        while uitem != 4:
            print('\nUtility Menu\nPlease make a selection.\n   1: Remove all stored files\n   2: Remove single IP + files\n   3: Backup all stored files to zip\n   4: Return to main menu')       
            try:
                uitem = input('bp_$>')
            except SyntaxError:
                uitem = None
            if uitem == 1:
                addr = removedata(addr)
            elif uitem == 2:
                addr = removeitem(addr)
            elif uitem == 3:
                print(3)
            elif uitem == 4:
                print("\nReturning to main menu.")
            else:
                print("You have entered an invalid selection.")
    except NameError:
        print("You have entered an invalid selection.")
    return addr
##### Utility Menu function --end--

##### Add IPs function --start--
def addips (addresses):
    print("\nPlease enter the IP or IP block with CIDR notation you wish to add.")
    try:
        newips = None
        #print(sys.version_info)
        if sys.version_info < (3, 0):
            print("python version < 3.0 detected...\n")
            inp = unicode(raw_input('new_ips>'))
        else:
            print("python 3.0+ detected...\n")
            inp = unicode(input('new_ips>'))
        newips = ipaddress.ip_network(inp)
    except TypeError:
        print("Invalid entry.")
        print(sys.exc_info()[0], sys.exc_info()[1])
        newips = None
    except ValueError:
        print("Error: Did you add extra characters or use an invalid starting IP/subnet mask combination?")
        newips = None
    if newips != None:
        for i in newips:
            if addresses[0] == None:
                addresses = [str(i)]
            else:
                addresses.append(str(i))
    return addresses
##### Add IPs function --end--

##### Scanner function --start--
def scanner (addresses):

    messages=["Runtime Messages:"]
    results=["Scan Results:"]

    if not os.path.exists(os.path.dirname("./bluepill_outputs")):
        print("No output directory found. Creating.")
        q = Popen(["mkdir", "bluepill_outputs"])
        (qoutput, qerr) = q.communicate()
        qexit_code = q.wait()
        messages.append("Mkdir errors:")
        messages.append(qerr)

    for i in addresses:
        if not os.path.isfile('./bluepill_outputs/' + i + '.xml'):
            print("running NMAP for " + i)
            p = Popen(["nmap", "-A", "-oX"] + ["./bluepill_outputs/" + i + ".xml"] + [str(i)], stdout=PIPE)
            (output, err) = p.communicate()
            exit_code = p.wait()
            results.append(output)
            if err != None:
                messages.append("NMAP errors for " + i + " :")
                messages.append(err)
    parse2enums(addresses)    
    return messages
##### Scanner function --end--

##### Clear IPs function --start--
def clearips (addresses):
    addresses = [None]
    return addresses
##### Clear IPs function --end--

##### Print Stored IPs function --start--
def printaddrs (addresses):
    a = 1
    print("\nIPs stored:")
    if addresses[0] != None:
        for i in addresses:
            print(str(a) + ": " + str(i))
            a = a + 1
    else:
        print(str(a) + ": None")
##### Print Stored IPs function --end--

##### Rebuild IP List function --start--
def rebuildips(addresses):
    files = os.listdir('./bluepill_outputs/')
    for f in files:
        if re.search("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", f):
            ip = re.search("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", f).group(0)
            if addresses[0] == None:
                addresses = [ip]
            else:
                addresses.append(ip)
    return addresses
##### Rebuild IP List function --end--

##### Remove Stored Data function --start--
def removedata(addr):
    addresses = [None]
    addresses = rebuildips(addresses)
    files = os.listdir('./bluepill_outputs/')
    for a in addresses:
        for f in files:
            if re.search(a, f):
                print(f)
                try:
                    os.remove('./bluepill_outputs/'+f)
                except OSError:
                    messages.append('No such file or directory.')
    addr = [None]
    return addr
##### Remove Stored Data function --end--

##### Remove Single Item function --start--
def removeitem(addr):
    print('\nPlease enter the IP address(es) you want to remove.\nNote that all associated files will also be removed.')
    try:
        remips = None
        #print(sys.version_info)
        if sys.version_info < (3, 0):
            print("python version < 3.0 detected...\n")
            inp = unicode(raw_input('new_ips>'))
        else:
            print("python 3.0+ detected...\n")
            inp = unicode(input('new_ips>'))
        remips = ipaddress.ip_network(inp)
    except TypeError:
        print("Invalid entry.")
        print(sys.exc_info()[0], sys.exc_info()[1])
        remips = None
    except ValueError:
        print("Error: Did you add extra characters or use an invalid starting IP/subnet mask combination?")
        remips = None
    files = os.listdir('./bluepill_outputs/')
    if remips != None:
        for ip in remips:
            for f in files:
                if re.search(str(ip), f):
                    try:
                        os.remove('./bluepill_outputs/'+f)
                    except OSError:
                        messages.append('No such file or directory')
            for a in addr:
                if a == str(ip):
                    addr.remove(a)
    return addr
##### Remove Single Item function --end--

##### XML Parse-to-enumerators --start--
def parse2enums(addresses):
    for i in addresses:
        etree = xml.etree.ElementTree.parse('./bluepill_outputs/'+ i + '.xml')
        etroot = etree.getroot()
        #print(etroot.tag, etroot.attrib)
        xmllooper(etroot, i)
##### XML Parse-to-enumerators --end--

##### XML Structure Loop --start--
def xmllooper(parent, ip):
    for child in parent:
        #print(child.tag, child.attrib)
        if child.tag == 'port':
            if child.get('portid') == "80":
                print(ip + " is running a webserver! Nikto time!")
                niktoscan(ip)
        xmllooper(child, ip)
##### XML Structure Loop --end--

##### Nikto Scan function --start--
def niktoscan(address):
    try:
        p = Popen(["nikto", "-h", address, "-output"] + ["./bluepill_outputs/nikto_" + address + ".xml"], stdout=PIPE)
        (output, err) = p.communicate()
        exit_code = p.wait()
        if err != None:
            messages.append("Nikto errors for " + address + " :")
            messages.append(err)
    except:
        print("something happened while trying to run Nikto")
##### Nikto Scan function --end--

##### Global vars --start--
messages = [None]
menuitem = None
addr = [None]
##### Global vars --end--

"""
try:
    if args.ip != None:
        addr = ipaddress.ip_network(unicode(args.ip))
    else:
        print("that's not valid, yo!")
        print(args.ip)
except:
    print("exception, yo!", sys.exc_info()[0], sys.exc_info()[1])
"""

##### Main loop --start--
while menuitem != 6:
    menuitem = menu(menuitem)
    try:
        if int(menuitem) == 1:
            addr = addips(addr)
        elif int(menuitem) == 2:
            messages = scanner(addr)
        elif int(menuitem) == 3:
            addr = clearips(addr)
        elif int(menuitem) == 4:
            print(4)
        elif int(menuitem) == 5:
            printaddrs(addr)
        elif int(menuitem) == 6:
            addr = rebuildips(addr)
        elif int(menuitem) == 7:
            addr = utilmenu(addr)
        elif int(menuitem) == 8:
            print("Exiting.\n")
            break
        else:
            print("Invalid selection. Please re-enter.\n")
    except TypeError:
        print("You entered an invalid selection. Try again.\n")
        print("exception, yo!", sys.exc_info()[0], sys.exc_info()[1])
    menuitem = None
##### Main loop --end--

# Final message output (non-error, informational)
for m in messages:
        print (m)
