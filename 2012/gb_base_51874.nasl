###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_base_51874.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# BASE 'base_qry_main.php' SQL Injection Vulnerability
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

tag_summary = "BASE is prone to an SQL-injection vulnerability because it fails
to sufficiently sanitize user-supplied data before using it in an
SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

BASE 1.4.5 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103414");
 script_bugtraq_id(51874);
 script_cve_id("CVE-2012-1017");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 9352 $");

 script_name("BASE 'base_qry_main.php' SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51874");
 script_xref(name : "URL" , value : "http://base.secureideas.net/");

 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-10 11:58:03 +0100 (Fri, 10 Feb 2012)");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("base_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("BASE/installed");

 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"BASE")) {

  if(version_is_equal(version: vers, test_version: "1.4.5")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
