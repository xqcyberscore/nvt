###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_op5_55255.nasl 6720 2017-07-13 14:25:27Z cfischer $
#
# op5 Monitor Unspecified SQL Injection Vulnerability
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

tag_summary = "op5 Monitor is prone to an unspecified SQL-injection vulnerability
because it fails to sufficiently sanitize user-supplied data before
using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

op5 Monitor versions 2.7.3 and prior are affected.";

tag_solution = "Reportedly, the issue is fixed in the beta version. Please contact the
vendor for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103557";
CPE = "cpe:/a:op5:monitor";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(55255);
 script_version ("$Revision: 6720 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:N");

 script_name("op5 Monitor Unspecified SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55255");

 script_tag(name:"last_modification", value:"$Date: 2017-07-13 16:25:27 +0200 (Thu, 13 Jul 2017) $");
 script_tag(name:"creation_date", value:"2012-08-30 11:27:11 +0200 (Thu, 30 Aug 2012)");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_op5_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("OP5/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(vers =  get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) {

  if(version_is_less_equal(version: vers, test_version: "2.7.3")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
