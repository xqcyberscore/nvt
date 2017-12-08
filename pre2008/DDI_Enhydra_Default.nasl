# OpenVAS Vulnerability Test
# $Id: DDI_Enhydra_Default.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Enhydra Multiserver Default Password
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2003 Digital Defense Inc.
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

tag_summary = "This system appears to be running the Enhydra application
server configured with the default administrator password
of 'enhydra'. A potential intruder could reconfigure this 
service and use it to obtain full access to the system.";

tag_solution = "Please set a strong password of the 'admin' account.";

if(description)
{
 script_id(11202);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-1999-0508");

 name = "Enhydra Multiserver Default Password";
 script_name(name);



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");

 script_copyright("This script is Copyright (C) 2003 Digital Defense Inc.");
 family = "General";
 script_family(family);

 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("Enhydra/banner");
 script_require_ports("Services/www", 8001);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:8001);
if ( ! port ) exit(0);

banner = get_http_banner(port:port);
if ( ! banner || "Enhydra" >!< banner ) exit(0);

if(get_port_state(port))
 {
   req = http_get(item:"/Admin.po?proceed=yes", port:port);
   req = req - string("\r\n\r\n");
   req = string(req, "\r\nAuthorization: Basic YWRtaW46ZW5oeWRyYQ==\r\n\r\n");
   buf = http_keepalive_send_recv(port:port, data:req);
  if("Enhydra Multiserver Administration" >< buf)
    {
        security_message(port);
    }   
}
