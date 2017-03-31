###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_40149.nasl 5263 2017-02-10 13:45:51Z teissa $
#
# Cacti 'rra_id' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "Cacti is prone to an SQL-injection vulnerability because it fails
to sufficiently sanitize user-supplied data before using it in an
SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

Cacti versions 0.8.7e and prior are vulnerable.";


if (description)
{
 script_id(100639);
 script_version("$Revision: 5263 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-10 14:45:51 +0100 (Fri, 10 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-05-14 12:04:31 +0200 (Fri, 14 May 2010)");
 script_cve_id("CVE-2010-2092");
 script_bugtraq_id(40149);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Cacti 'rra_id' Parameter SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40149");
 script_xref(name : "URL" , value : "http://cacti.net/");
 script_xref(name : "URL" , value : "http://www.php-security.org/2010/05/13/mops-2010-023-cacti-graph-viewer-sql-injection-vulnerability/index.html");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("cacti_detect.nasl");
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

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"cacti")) {

  if(version_is_less(version: vers, test_version: "0.8.7e")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
