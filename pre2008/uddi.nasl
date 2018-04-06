# OpenVAS Vulnerability Test
# $Id: uddi.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: UDDI detection
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net
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

tag_summary = "The tested Web server seems to be friendly to UDDI requests.  
The server could be potentially offering web services
under some other directory (we only tested the web root directory)";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.11140");
    script_version("$Revision: 9348 $");
    script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
    name = "UDDI detection";
    script_name(name);

    summary = "Find UDDI";
    script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
    script_copyright("This script is Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net");
    family = "General";
    script_family(family);
    script_dependencies("find_service.nasl");
    script_require_ports("Services/www", 80);
    script_tag(name : "summary" , value : tag_summary);
    exit(0);
}

#
# The script code starts here
#




include("uddi.inc");
include("http_func.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);
if(get_kb_item("Services/www/" + port + "/embedded") ) exit(0);
mypath = "/";

mymessage = create_uddi_xml(ktype:"UDDI_QUERY_FBUSINESS", path:mypath, key:"", name:"e");  #loop through ETAOIN?
soc = open_sock_tcp(port);

if(soc) 
{
  send(socket:soc, data:mymessage);
  getreply = http_recv(socket:soc);
  close(soc);
}
else
{
  exit(0);
}



mystr = strstr(getreply, "serviceKey");
if (!mystr) 
{
   soaptest = strstr(getreply,"soap:Envelope");
   if (soaptest) {
      mywarning = string("The server seems to accept UDDI queries.  This could indicate\n");
      mywarning = string(mywarning, " that the server is offering web services");
      log_message(port:port, data:mywarning);
      }
    exit(0);
}

flag = 0;
mykey = "";
for (i=12; flag < 1 ; i = i + 1) 
{                        #jump over servicekey=
    if ( (mystr[i] < "#") && (mystr[i] > "!") ) # BLECH!
        flag = flag + 1;
   else 
   	mykey = string(mykey, mystr[i]);
    
}

mymessage = create_uddi_xml(ktype:"UDDI_QUERY_GSERVICE_DETAIL", path:mypath, key:mykey);

soc = open_sock_tcp(port);
if (soc) 
{
   send(socket:soc, data:mymessage);
   getreply = http_recv(socket:soc);
}

if (egrep(pattern:mykey, string:getreply)) 
{
        mywarning = string("The server is accepting UDDI queries.  This indicates\n");
	mywarning = string(mywarning, " that the server is offering web services");
	log_message(port:port, data:mywarning);
        exit(0);
}

if (egrep(pattern: ".*200 OK.*", string:getreply)) 
{
        mywarning = string("The server seems to accept UDDI queries.  This could indicate\n");
	mywarning = string(mywarning, " that the server is offering web services");
	log_message(port:port, data:mywarning);
	exit(0);
}

