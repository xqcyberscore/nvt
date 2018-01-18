###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagiosxi_2009R1.3.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# Nagios XI < 2009R1.3 multiple vulnerabilities
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

tag_summary = "Nagios XI is prone to multiple vulnerabilities.

1. Nagios XI is prone to multiple cross-site scripting vulnerabilities
because it fails to properly sanitize user-supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

2. Nagios XI is prone to an SQL-injection vulnerability because it
fails to sufficiently sanitize user-supplied data before using it in
an SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

Versions prior to Nagios XI 2009R1.3 are vulnerable.";

tag_solution = "Reportedly, these issues have been fixed in Nagios XI 2009R1.3. Please
see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100778");
 script_version("$Revision: 8447 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)");
 script_bugtraq_id(42604);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Nagios XI < 2009R1.3 multiple vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42604");
 script_xref(name : "URL" , value : "http://www.nagios.com/products/nagiosxi");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/513248");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_nagios_XI_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"nagiosxi")) {
  if(version_is_less(version: vers, test_version: "2009R1.3")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
