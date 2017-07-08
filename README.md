# Description
This tool offers the following features:
  * Viewing multiple devices info simultaneously
  * Configure multiple devices simultaneously
  * Shutdown unused ports on access switches
  * Enable disabled ports on access switches
  * Convert ACL syntax from IOS to Junos and vice versa

This tool depends on [netmiko](https://github.com/ktbyers/netmiko) (for viewing/configuring devices) and [trigger](https://trigger.readthedocs.io/en/latest/) (for converting ACL syntax) modules, so installing netmiko and trigger modules prior to running this tool is a MUST.

# Installation
```
pip3 install cryptography
pip3 install paramiko
pip3 install netmiko
pip3 install colorama
```
For installing trigger module, please visit: [Trigger](https://trigger.readthedocs.io/en/latest/)

# Usage
Assign execute permission to the script:
```
# chmod a+x netdev_config.py
```

Run the tool and follow the instructions in each menu option:
```
# ./netdev_config

Please choose an option:
  1 - Run commands from terminal (suitable for viewing device's info)
  2 - Run commands from file (suitable for configuring devices)
  3 - Shutdown unused ports on access switches
  4 - Enable disabled ports on access switches
  5 - Convert IOS ACL to Junos ACL
  6 - Convert Junos ACL to IOS ACL
  0 - Exit
   
* Enter your choice:
```
