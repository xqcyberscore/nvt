###############################################################################
# OpenVAS Vulnerability Test
# $Id: postgresql_cve_2009_0922.nasl 5016 2017-01-17 09:06:21Z teissa $
#
# PostgreSQL Conversion Encoding Remote Denial of Service
# Vulnerability
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

tag_summary = "PostgreSQL is prone to a remote denial-of-service vulnerability.

  Exploiting this issue may allow attackers to terminate connections
  to the PostgreSQL server, denying service to legitimate users.";

tag_solution = "Updates are available. Update to newer Version.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100157";
CPE = "cpe:/a:postgresql:postgresql";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 5016 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-17 10:06:21 +0100 (Tue, 17 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)");
 script_bugtraq_id(34090);
 script_cve_id("CVE-2009-0922");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

 script_name("PostgreSQL Conversion Encoding Remote Denial of Service Vulnerability");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("postgresql_detect.nasl");
 script_require_ports("Services/postgresql", 5432);
 script_mandatory_keys("PostgreSQL/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34090");
 script_xref(name : "URL" , value : "http://www.postgresql.org/");
 exit(0);
}

include("version_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port)port = 5432;
if(!get_tcp_port_state(port))exit(0);

if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(version_in_range(version:ver, test_version:"8.3", test_version2:"8.3.6")  ||
   version_in_range(version:ver, test_version:"8.2", test_version2:"8.2.6")  ||
   version_in_range(version:ver, test_version:"8.1", test_version2:"8.1.11") ||
   version_in_range(version:ver, test_version:"8.0", test_version2:"8.0.17") ||
   version_in_range(version:ver, test_version:"7.4", test_version2:"7.4.19") ||
   version_in_range(version:ver, test_version:"7.3", test_version2:"7.3.21") ||
   version_in_range(version:ver, test_version:"7.2", test_version2:"7.2.7")  ||
   version_in_range(version:ver, test_version:"7.1", test_version2:"7.1.3")  ||
   version_in_range(version:ver, test_version:"7.0", test_version2:"7.0.3")  ||
   version_in_range(version:ver, test_version:"6.5", test_version2:"6.5.3"))
{
     security_message(port:port);
     exit(0);
} 

exit(0); 
