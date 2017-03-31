###############################################################################
# OpenVAS Vulnerability Test
# $Id: mysql_multiple_vuln.nasl 5002 2017-01-13 10:17:13Z teissa $
#
# MySQL multiple Vulnerabilities
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

tag_summary = "MySQL is prone to a security-bypass vulnerability and to to a local
privilege-escalation vulnerability.

An attacker can exploit the security-bypass issue to bypass certain
security restrictions and obtain sensitive information that may lead
to further attacks.

Local attackers can exploit the local privilege-escalation issue to
gain elevated privileges on the affected computer.

Versions prior to MySQL 5.1.41 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100356";
CPE = "cpe:/a:mysql:mysql";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 5002 $");
 script_cve_id("CVE-2009-4030");
 script_tag(name:"last_modification", value:"$Date: 2017-01-13 11:17:13 +0100 (Fri, 13 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-11-20 12:35:38 +0100 (Fri, 20 Nov 2009)");
 script_bugtraq_id(37075);
 script_tag(name:"cvss_base", value:"4.4");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_name("MySQL multiple Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37076");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37075");
 script_xref(name : "URL" , value : "http://dev.mysql.com/doc/refman/5.1/en/news-5-1-41.html");
 script_xref(name : "URL" , value : "http://www.mysql.com/");

 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 script_mandatory_keys("MySQL/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("version_func.inc");
include("misc_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_tcp_port_state(port))exit(0);

if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
ver = eregmatch(pattern:"[0-9.]+", string: ver);

if(isnull(ver[0]))exit(0);

if(ver[0] =~ "5\.") {
  if(version_is_less(version:ver[0], test_version:"5.1.41") ) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
