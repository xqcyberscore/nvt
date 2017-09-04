###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_46084.nasl 7044 2017-09-01 11:50:59Z teissa $
#
# PostgreSQL 'intarray' Module 'gettoken()' Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "PostgreSQL is prone to a buffer-overflow vulnerability because
the application fails to perform adequate boundary checks on
user-supplied data. The issue affects the 'intarray' module.

An authenticated attacker can leverage this issue to execute arbitrary
code within the context of the vulnerable application. Failed exploit
attempts will result in a denial-of-service condition.

The issue affect versions prior to 8.2.20, 8.3.14, 8.4.7, and 9.0.3.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103054";
CPE = "cpe:/a:postgresql:postgresql";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 7044 $");
 script_tag(name:"last_modification", value:"$Date: 2017-09-01 13:50:59 +0200 (Fri, 01 Sep 2017) $");
 script_tag(name:"creation_date", value:"2011-02-02 13:26:27 +0100 (Wed, 02 Feb 2011)");
 script_bugtraq_id(46084);
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4015");

 script_name("PostgreSQL 'intarray' Module 'gettoken()' Buffer Overflow Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46084");
 script_xref(name : "URL" , value : "http://www.postgresql.org/");
 script_xref(name : "URL" , value : "http://www.postgresql.org/about/news.1289");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("postgresql_detect.nasl");
 script_require_ports("Services/postgresql", 5432);
 script_mandatory_keys("PostgreSQL/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("version_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);

if(!port)port = 5432;
if(!get_tcp_port_state(port))exit(0);

if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(version_in_range(version:ver,test_version:"8.2",test_version2:"8.2.19") ||
   version_in_range(version:ver,test_version:"8.3",test_version2:"8.3.13") ||
   version_in_range(version:ver,test_version:"8.4",test_version2:"8.4.6")  ||
   version_in_range(version:ver,test_version:"9.0",test_version2:"9.0.2")) {
     security_message(port:port);
     exit(0);
}   

exit(0);

