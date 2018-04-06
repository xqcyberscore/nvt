###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openengine_49794.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# openEngine 'id' Parameter SQL Injection Vulnerability
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

tag_summary = "openEngine is prone to an SQL Injection vulnerability because it
fails to sufficiently sanitize user-supplied data before using it in
an SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database implementation.

openEngine 2.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103278");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-28 12:51:43 +0200 (Wed, 28 Sep 2011)");
 script_bugtraq_id(49794);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("openEngine 'id' Parameter SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49794");
 script_xref(name : "URL" , value : "http://www.rul3z.de/advisories/SSCHADV2011-019.txt");
 script_xref(name : "URL" , value : "http://www.openengine.de/");

 script_tag(name:"qod_type", value:"remote_active");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_openengine_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"openengine"))exit(0);
   
url = string(dir,"/cms/website.php?id=/de/sendpage.htm%27)%20AND%201=1%20AND%20(%27a%27=%27a&key="); 

if(http_vuln_check(port:port, url:url,pattern:"Warning: mysql_num_fields")) {
    
  security_message(port:port);
  exit(0);

}

exit(0);
