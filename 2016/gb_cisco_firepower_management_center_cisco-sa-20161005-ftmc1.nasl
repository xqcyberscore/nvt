###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firepower_management_center_cisco-sa-20161005-ftmc1.nasl 5101 2017-01-25 11:40:28Z antu123 $
#
# Cisco Firepower Management Center Console Authentication Bypass Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.106334");
 script_cve_id("CVE-2016-6434");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 5101 $");

 script_name("Cisco Firepower Management Center Console Authentication Bypass Vulnerability");

 script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-ftmc1");

 script_tag(name: "vuldetect" , value:"Check the version.");

 script_tag(name: "solution" , value:"No solution or patch is available as of 24th January, 2017. Information
regarding this issue will be updated once the solution details are available.");

 script_tag(name: "summary" , value:"A vulnerability in the web console of Cisco Firepower Management Center
could allow an authenticated, local attacker to bypass authentication and access sensitive information.");

 script_tag(name: "insight", value: "The vulnerability is due to the use of static credentials by the database
on an affected system.");

 script_tag(name: "impact", value: "An authenticated user who can access the command-line interface (CLI) for an
affected system may be able to leverage this vulnerability to access information in the database directly from a
local shell.");

 script_tag(name:"qod_type", value:"package");

 script_tag(name:"solution_type", value:"NoneAvailable");

 script_tag(name:"last_modification", value:"$Date: 2017-01-25 12:40:28 +0100 (Wed, 25 Jan 2017) $");
 script_tag(name:"creation_date", value:"2016-10-06 11:03:55 +0700 (Thu, 06 Oct 2016)");
 script_category(ACT_GATHER_INFO);
 script_family("CISCO");
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_dependencies("gb_cisco_firepower_management_center_version.nasl");
 script_mandatory_keys("cisco_firepower_management_center/version");
 exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version == '6.0.1' )
{
  report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

