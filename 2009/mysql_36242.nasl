###############################################################################
# OpenVAS Vulnerability Test
# $Id: mysql_36242.nasl 5002 2017-01-13 10:17:13Z teissa $
#
# MySQL 5.x Unspecified Buffer Overflow Vulnerability
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

tag_summary = "MySQL is prone to a buffer-overflow vulnerability because if fails to
perform adequate boundary checks on user-supplied data.

An attacker can leverage this issue to execute arbitrary code within
the context of the vulnerable application. Failed exploit attempts
will result in a denial-of-service condition.

This issue affects MySQL 5.x; other versions may also be vulnerable.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100271";
CPE = "cpe:/a:mysql:mysql";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 5002 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-13 11:17:13 +0100 (Fri, 13 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-09-07 09:47:24 +0200 (Mon, 07 Sep 2009)");
 script_bugtraq_id(36242);
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

 script_name("MySQL 5.x Unspecified Buffer Overflow Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36242");
 script_xref(name : "URL" , value : "http://www.mysql.com/");
 script_xref(name : "URL" , value : "http://intevydis.com/company.shtml");

 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
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
ver = eregmatch(pattern:"[0-9.]+", string: ver);

if(isnull(ver[0]))exit(0);

if(version_in_range(version:ver[0], test_version:"5", test_version2:"5.1.32") ) {
     security_message(port:port);
     exit(0);
}

exit(0);
