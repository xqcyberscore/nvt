###############################################################################
# OpenVAS Vulnerability Test
# $Id: invision_power_board_37208.nasl 4970 2017-01-09 15:00:59Z teissa $
#
# Invision Power Board Local File Include and SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "Invision Power Board is prone to a local file-include vulnerability
and multiple SQL-injection vulnerabilities because it fails to
properly sanitize user-supplied input.

An attacker can exploit the local file-include vulnerability using directory-
traversal strings to view and execute arbitrary local files within the
context of the webserver process. Information harvested may aid in
further attacks.

The attacker can exploit the SQL-injection vulnerabilities to
compromise the application, access or modify data, or exploit latent
vulnerabilities in the underlying database.

Invision Power Board 3.0.4 and 2.3.6 are vulnerable; other versions
may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100381";
CPE = "cpe:/a:invision_power_services:invision_power_board";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 4970 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-09 16:00:59 +0100 (Mon, 09 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-12-08 22:02:24 +0100 (Tue, 08 Dec 2009)");
 script_bugtraq_id(37208);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Invision Power Board Local File Include and SQL Injection Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37208");
 script_xref(name : "URL" , value : "http://www.invisionpower.com/community/board/index.html");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/508207");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("invision_power_board_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_mandatory_keys("invision_power_board/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!get_port_state(port))exit(0);

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "3.0.4") ||
     version_is_equal(version: vers, test_version: "2.3.6")
     ) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
