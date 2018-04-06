# OpenVAS Vulnerability Test
# $Id: DDI_AirConnect_Default_Password.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: AirConnect Default Password
#
# Authors:
# H D Moore
#
# Copyright:
# Copyright (C) 2002 Digital Defense Inc.
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

tag_summary = "This AirConnect wireless access point still has the 
    default password set for the web interface. This could 
    be abused by an attacker to gain full control over the
    wireless network settings.";

tag_solution = "Change the password to something difficult to
    guess via the web interface.";

# Information about the AP provided by Brian Caswell

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.10961");
    script_version("$Revision: 9348 $");
    script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"4.6");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
    script_cve_id("CVE-1999-0508");
    name = "AirConnect Default Password";
    script_name(name);



    summary = "3Com AirConnect AP Default Password";


    script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");

    script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");

    family = "Privilege escalation";
    script_family(family);
    script_dependencies("http_version.nasl");
    script_require_ports("Services/www");
    
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

function sendrequest (request, port)
{
    reply = http_keepalive_send_recv(data:request, port:port);
    if( reply == NULL ) exit(0);
    return(reply);
}

#
# The script code starts here
#


port = get_http_port(default:80);

if(!get_port_state(port)){ exit(0); }

req = string("GET / HTTP/1.0\r\nAuthorization: Basic Y29tY29tY29tOmNvbWNvbWNvbQ==\r\n\r\n");

reply = sendrequest(request:req, port:port);

if ("SecuritySetup.htm" >< reply)
{
    security_message(port:port);
}
