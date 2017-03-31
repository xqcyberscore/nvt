# OpenVAS Vulnerability Test
# $Id: X.nasl 2837 2016-03-11 09:19:51Z benallard $
# Description: X Server
#
# Authors:
# John Jackson <jjackson@attrition.org>
# Pavel Kankovsky <kan@dcit.cz>:
# proper X11 protocol handling
# Changes by rd :
# - description
# - minor style issues
# - script_require_ports()
#
# Copyright:
# Copyright (C) 2000 John Jackson
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "This plugin detects X Window servers.

X11 is a client - server protocol. Basically, the server is in charge of the 
screen, and the clients connect to it and send several requests like drawing 
a window or a menu, and the server sends events back to the clients, such as 
mouse clicks, key strokes, and so on...

An improperly configured X server will accept connections from clients from 
anywhere. This allows an attacker to make a client connect to the X server to 
record the keystrokes of the user, which may contain sensitive information,
such as account passwords.
This can be prevented by using xauth, MIT cookies, or preventing
the X server from listening on TCP (a Unix sock is used for local 
connections)";

# Fri May 12 15:58:21 GMT 2000
# Test for an "open" X server
# An X server's access control is disabled (e.g. through an "xhost +" command) and 
# allows anyone to connect to the server. 

if(description)
{
  script_id(10407);
  script_version("$Revision: 2837 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-1999-0526");

  name = "X Server";
  script_name(name);

 summary = "An X Window System Server is present";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 family = "General";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports(6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009);
 
 script_copyright("This script is Copyright (C) 2000 John Jackson");
  script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.10407";
SCRIPT_DESC = "X Server";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

function riptext(data, begin, length)
{
  count=begin;
  end=begin+length-1;
  if (end >= strlen(data))
    end = strlen(data) - 1;
  text="";
  for(count=begin;count<=end;count=count+1)
  {
    text = string(text + data[count]);
  }
  return(text);
}

####   ##   # ###
# # # #  #  # #  #
# # #  ## # # #  #

#
# The format of client request
#  CARD8    byteOrder (66 'B'=MSB, 108 'l'=LSB)
#  BYTE     padding
#  CARD16   majorVersion, minorVersion
#  CARD16   nBytesAuthProto  (authorization protocol)
#  CARD16   nBytesAuthString (authorization data)
#  CARD     padding
#  STRING8  authProto
#  STRING8  authString
#
# The format of server response:
#  CARD8    success (0=Failed, 1=Success, 2=Authenticate)
#  BYTE     lengthReason (unused if success==1)
#  CARD16   majorVersion, minorVersion (unused if success==2)
#  CARD16   length (of additional data)
#  STRING8  reason (for success==0 or success==1)
#
# CARD16 values are endian-sensitive; endianness is determined by
# the first byte sent by a client
#

# hmm....it might look like a good idea to raise the higher limit to test
# connections forwarded by OpenSSH but it is pointless because OpenSSH
# does not process connections without a cookie--everything you'll get
# will be a stale connection

for(port=6000; port<6010; port++)
{
  if(get_port_state(port))
  { 
    tcpsock = open_sock_tcp(port);
    if(tcpsock)
    {
    xwininfo = raw_string(108,0,11,0,0,0,0,0,0,0,0,0);
    # change the xwininfo bytes above to force servers to send a version mismatch

    send(socket:tcpsock, data:xwininfo);
    tcpresult = recv(socket:tcpsock, length:32);
    close(tcpsock);

    if(tcpresult && strlen(tcpresult) >= 8)
    {
      result = ord(tcpresult[0]);

      if (result == 0) # Failed
          {
            major = ord(tcpresult[2]) + 256 * ord(tcpresult[3]);
            minor = ord(tcpresult[4]) + 256 * ord(tcpresult[5]);
            ver = strcat(major, ".", minor);
            set_kb_item(name: "X11/"+port+"/version", value: ver);

            ## build cpe and store it as host_detail
            register_cpe(tmpVers: ver, tmpExpr:"^([0-9.]+([a-z0-9]+)?)",tmpBase:"cpe:/a:x.org:x11:");

            textresult=riptext(data:tcpresult, begin:8, length:ord(tcpresult[1]));
            set_kb_item(name: "X11/"+port+"/answer", value: textresult);
            set_kb_item(name: "X11/"+port+"/open", value: FALSE);

	    report = string("This X server does *not* allow any client to connect to it\n",
	    	"however it is recommended that you filter incoming connections\n",
		"to this port as attacker may send garbage data and slow down\n",
		"your X session or even kill the server.\n\n",
		"Here is the server version : ", ver, "\n",
		"Here is the message we received : ", textresult, "\n\n",
		"Solution: filter incoming connections to ports 6000-6009");
            security_message(port:port, data:report);
	    register_service(port: port, proto: "X11");
          }

      if (result == 1) # Success
          {
            major = ord(tcpresult[2]) + 256 * ord(tcpresult[3]);
            minor = ord(tcpresult[4]) + 256 * ord(tcpresult[5]);
            ver = strcat(major, ".", minor);
            set_kb_item(name: "X11/"+port+"/version", value: ver);

            ## build cpe and store it as host_detail
            register_cpe(tmpVers: ver, tmpExpr:"^([0-9.]+([a-z0-9]+)?)",tmpBase:"cpe:/a:x.org:x11:");

            textresult=riptext(data:tcpresult, begin:40, length:ord(tcpresult[24]));
            set_kb_item(name: "X11/"+port+"/answer", value: textresult);
            set_kb_item(name: "X11/"+port+"/open", value: TRUE);

	 # security_message moved to open_X11_server.nasl
	    register_service(port: port, proto: "X11");
          }

      if (result == 2) # Authenticate
          {
            textresult=riptext(data:tcpresult, begin:8, length:ord(tcpresult[1]));
            set_kb_item(name: "X11/"+port+"/answer", value: textresult);
            set_kb_item(name: "X11/"+port+"/open", value: FALSE);

	    report = string("This X server does *not* allow any client to connect to it\n",
	    	"however it is recommended that you filter incoming connections\n",
		"to this port as attacker may send garbage data and slow down\n",
		"your X session or even kill the server.\n\n",
		"Here is the message we received : ", textresult, "\n\n",
		"Solution: filter incoming connections to ports 6000-6009");
            security_message(port:port, data:report);
	    register_service(port: port, proto: "X11");
          }

    } #if tcpresult
   } #if tcpsock
  } #if port open
} #for portnum

exit(0);
