###############################################################################
# OpenVAS Vulnerability Test
# $Id: mysql_37640.nasl 5394 2017-02-22 09:22:42Z teissa $
#
# MySQL 5.0.51a Unspecified Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer
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

tag_summary = "MySQL 5.0.51a is prone to an unspecified remote code-execution
vulnerability.

Very few technical details are currently available.

An attacker can leverage this issue to execute arbitrary code within
the context of the vulnerable application. Failed exploit attempts
will result in a denial-of-service condition.

This issue affects MySQL 5.0.51a; other versions may also be
vulnerable.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100436";
CPE = "cpe:/a:mysql:mysql";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 5394 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-22 10:22:42 +0100 (Wed, 22 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-01-11 11:18:50 +0100 (Mon, 11 Jan 2010)");
 script_cve_id("CVE-2009-4484");
 script_bugtraq_id(37640);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("MySQL 5.0.51a Unspecified Remote Code Execution Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37640");
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/dailydave/2010-q1/0002.html");
 script_xref(name : "URL" , value : "http://www.mysql.com/");
 script_xref(name : "URL" , value : "http://intevydis.com/mysql_demo.html");

 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 script_mandatory_keys("MySQL/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("version_func.inc");
include("misc_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_tcp_port_state(port))exit(0);

if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
if(isnull(ver))exit(0);

if(ver =~ "5.0.51a") {
  security_message(port:port);
  exit(0);
}

exit(0);
