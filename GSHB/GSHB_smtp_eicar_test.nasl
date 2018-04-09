###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_smtp_eicar_test.nasl 9365 2018-04-06 07:34:21Z cfischer $
#
# Sent Eicar Testfiles
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# Set in an Workgroup Environment under Vista with enabled UAC this DWORD to access WMI:
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\LocalAccountTokenFilterPolicy to 1
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "Sent Eicar Testfiles";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96053");
  script_version("$Revision: 9365 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:34:21 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_app");  
  script_name("Sent Eicar Testfiles");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
   
#  script_require_ports("Services/smtp", 25);
  script_dependencies("find_service.nasl", "smtp_settings.nasl");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");


fromaddr = smtp_from_header();
toaddr = smtp_to_header();

portlist = get_kb_list("Services/smtp");
foreach p (portlist) if (p == "25") Port=p;

if(!port)port = 25;

if(!get_port_state(port)){
    set_kb_item(name:"GSHB/Eicar", value:"error");    
    set_kb_item(name:"GSHB/Eicar/log", value:"get_port_state on Port " + port + " failed.");      
exit(0);
}


s = open_sock_tcp(port);
if (!s){ 
    set_kb_item(name:"GSHB/Eicar", value:"error");    
    set_kb_item(name:"GSHB/Eicar/log", value:"open_sock_tcp on Port " + port + " failed.");            
exit(0);
}

buff = smtp_recv_banner(socket:s);

send(socket: s, data: string("HELO greenbone.com\r\n"));
buff = recv_line(socket:s, length:2048);

# MIME attachment

header = string("From: ", fromaddr, "\r\nTo: ", toaddr, "\r\n",
	"Organization: OpenVAS Greenbone Team\r\nMIME-Version: 1.0\r\n");

msg="Subject: OpenVAS antivirus Eicar base64 attachments
Content-Type: multipart/mixed;
 boundary=------------000407060703090403010006

This is a multi-part message in MIME format.
--------------000407060703090403010006
Content-Type: text/plain; charset=ISO-8859-1
Content-Transfer-Encoding: 7bit

This Mail should include the following Files:

eicar.com (an Eicar testfile) http://www.eicar.org/anti_virus_test_file.htm
eicar.txt (an Eicar testfile)
level1.zip; which includes test.txt (an Eicar testfile)
level2.zip; which includes level1.zip
level3.zip; which includes level2.zip
level4.zip; which includes level3.zip

If all attachments included and the Content not cleaned, 
you have an problem with your Antivirus-Engine.

################################################################################

Diese Mail sollte folgende Anhänge anthalten:

eicar.com (ein Eicar Testfile) http://www.eicar.org/anti_virus_test_file.htm
eicar.txt (ein Eicar Testfile)
level1.zip; mit eingeschlossem File: test.txt (ein Eicar Testfile)
level2.zip; mit eingeschlossem File: level1.zip
level3.zip; mit eingeschlossem File: level2.zip
level4.zip; mit eingeschlossem File: level3.zip

Wenn alle Anhänge enthalten sind und der Inhalt der Dateien
nicht bereinigt wurden, haben Sie ein Problem mit Ihrer Antivirus Lösung.


--------------000407060703090403010006
Content-Type: application/octet-stream; name=eicar.com
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename=eicar.com

WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNU
LUZJTEUhJEgrSCo=

--------------000407060703090403010006
Content-Type: text/plain; name=eicar.txt
Content-Transfer-Encoding: base64
Content-Disposition: inline; filename=eicar.txt

WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNU
LUZJTEUhJEgrSCo=

--------------000407060703090403010006
Content-Type: application/x-zip-compressed; name=level1.zip
Content-Transfer-Encoding: base64
Content-Disposition: inline; filename=level1.zip

UEsDBBQAAgAIAHdnizs8z1FoRgAAAEQAAAAIAAAAdGVzdC50eHSLMPVXDFB1cAyINokJiIowNdEI
iNM0d3bWNK9VcfV0dgzSDQ5x9HNxDHLRdfQL8QzzDAoN1g1xDQ7RdfP0cVVU8dD20AIAUEsBAhQA
FAACAAgAd2eLOzzPUWhGAAAARAAAAAgAAAAAAAAAAAAgAAAAAAAAAHRlc3QudHh0UEsFBgAAAAAB
AAEANgAAAGwAAAAAAA==

--------------000407060703090403010006
Content-Type: application/x-zip-compressed; name=level2.ZIP
Content-Transfer-Encoding: base64
Content-Disposition: inline; filename=level2.ZIP

UEsDBBQAAgAIABxNQzwFCLVLigAAALgAAAAKAAAAbGV2ZWwxLnppcAvwZmYRYWBi4GAoT++2tjkf
mOHGwMDgAsQcQFySWlyiV1JR0m3wNZwnoLSAp8Osk7Ojy8D0IkfHZZPysmsm60MLv5aU8Vzi5Sv8
UlzIU3Sx9Av3R57PPFy813gLefkuln7+Uhga8vHCtwtMDAHejEwiDLhtgwAFKA2zO8CblQ3EZwRC
MyCdA5YFAFBLAQIUABQAAgAIABxNQzwFCLVLigAAALgAAAAKAAAAAAAAAAAAIAAAAAAAAABsZXZl
bDEuemlwUEsFBgAAAAABAAEAOAAAALIAAAAAAA==

--------------000407060703090403010006
Content-Type: application/x-zip-compressed; name=level3.ZIP
Content-Transfer-Encoding: base64
Content-Disposition: inline; filename=level3.ZIP

UEsDBBQAAgAIADdNQzy+FNfB1gAAAAABAAAKAAAAbGV2ZWwyLlpJUAvwZmYRYWBi4GCQ8XW2YeXY
6t3FwMCwA4i5gDgntSw1x1CvKrOA+0NammBiQtKDBA3/99u2WcrPeHjswIEHTEdkHGImRcUsCg8K
vJT7wXSO+oItDcsPr5m8efHpA1+U3I+nTv60KVvttTP3/mlTPsY8eqr9JyjmRHDJxi/c393nnbeJ
2XO9grvyp960un9BElKfPh7azu3Dw3ivx0eJZ0duMwOrBu9m6wOzp/IeSWdxMlaYyzyNlSHAm5FJ
hAG3myFAAUojfBDgzcoGEmEEQgsgvQksDwBQSwECFAAUAAIACAA3TUM8vhTXwdYAAAAAAQAACgAA
AAAAAAAAACAAAAAAAAAAbGV2ZWwyLlpJUFBLBQYAAAAAAQABADgAAAD+AAAAAAA=

--------------000407060703090403010006
Content-Type: application/x-zip-compressed; name=level4.ZIP
Content-Transfer-Encoding: base64
Content-Disposition: inline; filename=level4.ZIP

UEsDBBQAAgAIAEVNQzx1FDMNJgEAAEwBAAAKAAAAbGV2ZWwzLlpJUAvwZmYRYWBi4GAw93W22Sdy
/eA1BiBgZGDgAlI5qWWpOUZ6UZ4B3B/S0gQTE5IeJEz4WLot8emNV3ePHjiwgbljZ4OF+lYd0+MB
67U2N/x2jpqVkOR0qZmF9//329siT52vqHhzoJHdxz1FJknN9agOFz/Xnim/D5b0/WrS5T3Nv37m
nsqPL5njp9zpX+73b4tm9Nutxt//ZQbbHbOpWvVXXeOZS8HJY/p37t99Pnd7583ivU27Py2/t2VX
vaNQ0Hw7uVvn3h4+XLH+uHtnunueMfNqtvdpr5k3L/8k55leaBQ247RN71TFA7MnerYwbp+t6MDo
pVwj8ODsKTahRBYnboW9nDr8DAHejEwiDLj9DwEKUBoRGgHerGwQZYwMFkD6H1geAFBLAQIUABQA
AgAIAEVNQzx1FDMNJgEAAEwBAAAKAAAAAAAAAAAAIAAAAAAAAABsZXZlbDMuWklQUEsFBgAAAAAB
AAEAOAAAAE4BAAAAAA==

--------------000407060703090403010006--";
msg = ereg_replace(pattern:string("\n"), string:msg, replace:string("\r\n"));

v=smtp_send_socket(socket:s, from: fromaddr, to: toaddr, body: header+msg);


send(socket: s, data: string("QUIT\r\n"));
close(s);

if (v > 0) {
  log_message(port: port, 
	data:string(	"The Eicar Testfiles was sent ", v, 
			" times. If there is an antivirus in your MTA, it might\n",
			"have blocked it. Please check the default OpenVAS Mailfolder right now, as it is\n",
			"not possible to do so remotely\n")); 
  set_kb_item(name:"GSHB/Eicar", value:"true");                    
}else if (v == 0) {
  log_message(port: port, 
	data: "For some reason, we could not send the Eicar Testfiles to this MTA");
  set_kb_item(name:"GSHB/Eicar", value:"fail");        
}
exit(0); 
