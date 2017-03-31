###############################################################################
# OpenVAS Vulnerability Test
# $Id: mysql_29106.nasl 5002 2017-01-13 10:17:13Z teissa $
#
# MySQL MyISAM Table Privileges Secuity Bypass Vulnerability
#
# Authors
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

tag_summary = "According to its version number, the remote version of MySQL is
  prone to a security-bypass vulnerability.

  An attacker can exploit this issue to gain access to table files created by
  other users, bypassing certain security restrictions.

  NOTE 1: This issue was also assigned CVE-2008-4097 because
  CVE-2008-2079 was incompletely fixed, allowing symlink attacks.

  NOTE 2: CVE-2008-4098 was assigned because fixes for the vector
  described in CVE-2008-4097 can also be bypassed.

  This issue affects versions prior to MySQL 4 (prior to 4.1.24) and
  MySQL 5 (prior to 5.0.60).";

tag_solution = "Updates are available. Update to newer Version.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100156";
CPE = "cpe:/a:mysql:mysql";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 5002 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-13 11:17:13 +0100 (Fri, 13 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-04-23 21:21:19 +0200 (Thu, 23 Apr 2009)");
 script_bugtraq_id(29106);
 script_cve_id("CVE-2008-2079","CVE-2008-4097","CVE-2008-4098");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

 script_name("MySQL MyISAM Table Privileges Secuity Bypass Vulnerability");


 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 script_mandatory_keys("MySQL/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/29106");
 exit(0);
}

include("version_func.inc");
include("misc_func.inc");
include("host_details.inc");


if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_tcp_port_state(port))exit(0);

if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(version_in_range(version:ver, test_version:"4", test_version2:"4.1.24") ||
   version_in_range(version:ver, test_version:"5", test_version2:"5.0.60") ) {
     security_message(port:port);
     exit(0);
} 

exit(0); 
