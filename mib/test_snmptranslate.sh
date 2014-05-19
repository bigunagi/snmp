#!/bin/sh
#snmptranslate -Le -M +  -m all -On $@
#if [ "$#" == "0" ];then
#    snmptranslate -Lo -M ./JuniperMibs/:./StandardMibs/:./iana/:./ieft/ -m ALL -Pu -Tso 
#else
    #snmptranslate -Lo -M ~/.snmp/mibs/JuniperMibs/:~/.snmp/mibs/StandardMibs/:~/.snmp/mibs/iana/:~/.snmp/mibs/ieft/ -m ALL -On $@
    snmptranslate -Lo -M /Users/nash/.snmp/mibs/NetSNMP:/Users/nash/.snmp/mibs/JuniperMibs:/Users/nash/.snmp/mibs/StandardMibs:/Users/nash/.snmp/mibs/iana:/Users/nash/.snmp/mibs/ieft -m ALL -On $@
    #snmptranslate -Lo -M /Users/nash/.snmp/mibs -m ALL -On $@
#fi
