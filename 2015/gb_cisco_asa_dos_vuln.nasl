###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_dos_vuln.nasl 2015-10-07 18:52:56 +0530 Oct$
#
# Cisco ASA DoS Vulnerability
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:cisco:asa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805759");
  script_version("$Revision: 6513 $");
  script_cve_id("CVE-2015-4241");
  script_bugtraq_id(75581);
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-04 11:59:28 +0200 (Tue, 04 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-10-07 18:52:56 +0530 (Wed, 07 Oct 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("Cisco ASA DoS Vulnerability");

  script_tag(name: "summary" , value:"This host has Cisco ASA
  and is prone to dos vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to improper handling of
  OSPFv2 packets by an affected system.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Cisco ASA 9.3.2");

  script_tag(name: "solution" , value:"Apply the patch from Cisco.
  For updates refer to http://www.cisco.com/");

  script_xref(name : "URL" , value : "http://tools.cisco.com/security/center/viewAlert.x?alertId=39641");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork: TRUE ) ) exit( 0 );
compver = ereg_replace(string:version, pattern:"\(([0-9.]+)\)", replace:".\1");

if (version_is_equal(version:compver, test_version:"9.3.2"))
{
  report = 'Installed Version: ' + compver + '\nFixed Version: Apply the appropriate updates from Cisco. \n';
  security_message(data:report);
  exit(0);
}
exit(0);

