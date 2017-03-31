# OpenVAS Vulnerability Test
# $Id: kayako_sql_injection.nasl 3520 2016-06-15 04:22:26Z ckuerste $
# Description: Kayako eSupport SQL Injection and Cross-Site-Scripting
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.16022");
 script_version("$Revision: 3520 $");
 script_tag(name:"last_modification", value:"$Date: 2016-06-15 06:22:26 +0200 (Wed, 15 Jun 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1412", "CVE-2004-1413");
 script_bugtraq_id(12037);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_name("Kayako eSupport SQL Injection and Cross-Site-Scripting");
 script_summary("Checks for the presence of an SQL and XSS in Kayako");
 script_category(ACT_ATTACK);
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : "Upgrade to the newest version of this software");
 script_tag(name : "summary" , value : "The remote host is running a version of Kayako eSupport which is vulnerable
 to a SQL injection vulnerability as well as a cross site scripting.");

 script_tag(name:"qod_type", value:"remote_app");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(!can_host_php(port:port))exit(0);

foreach dir (make_list_unique("/", cgi_dirs(port:port), "/support/esupport", "/support")) {

  if( dir == "/" ) dir = "";

  req = http_get(item: dir, "/index.php?_a=knowledgebase&_j=search&searchm=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL )exit(0);

  if(r =~ "HTTP/1\.. 200" && "<script>foo</script>" >< r) {
 	security_message(port:port);
	exit(0);
  }
}

exit(99);
