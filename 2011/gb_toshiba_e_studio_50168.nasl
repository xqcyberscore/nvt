###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_toshiba_e_studio_50168.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Multiple Toshiba e-Studio Devices Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "Multiple Toshiba e-Studio devices are prone to a security-bypass
vulnerability.

Successful exploits will allow attackers to bypass certain security
restrictions and gain access in the context of the device.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103301");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-10-18 13:33:12 +0200 (Tue, 18 Oct 2011)");
 script_bugtraq_id(50168);

 script_name("Multiple Toshiba e-Studio Devices Security Bypass Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50168");
 script_xref(name : "URL" , value : "http://www.eid.toshiba.com.au/n_mono_search.asp");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("General");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 8080);
 script_mandatory_keys("TOSHIBA/banner");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server: TOSHIBA" >!< banner)exit(0);

url = string("/TopAccess//Administrator/Setup/ScanToFile/List.htm"); 

if(http_vuln_check(port:port, url:url,pattern:"<TITLE>Save as file Setting",extra_check:make_list("Password","Protocol","Server Name"))) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
