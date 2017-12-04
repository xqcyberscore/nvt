###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intouch_machine_edition_stack_bof_vuln_nov17.nasl 7905 2017-11-24 12:58:24Z santu $
#
# InTouch Machine Edition Unspecified Stack Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:schneider_electric:intouch_machine_edition";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812217");
  script_version("$Revision: 7905 $");
  script_cve_id("CVE-2017-14024");
  script_bugtraq_id(101779);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-24 13:58:24 +0100 (Fri, 24 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-20 14:22:07 +0530 (Mon, 20 Nov 2017)");
  script_name("InTouch Machine Edition Unspecified Stack Buffer Overflow Vulnerability (Windows)");

  script_tag(name: "summary" , value: "This host is installed with InTouch Machine Edition
  and is prone to an unspecified stack buffer overflow vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the
  help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaw is due to an unspecified 
  stack-based buffer overflow error.");

  script_tag(name: "impact" , value: "Successful exploitation will allow
  a remote attacker to remotely execute code with high privileges.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Schneider Electric InTouch Machine Edition
  8.0 SP2 Patch 1 and prior versions on Windows.");

  script_tag(name: "solution" , value:"Upgrade to InTouch Machine Edition
  version 8.1 or later. For updates refer to http://www.indusoft.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name: "URL" , value : "https://ics-cert.us-cert.gov/advisories/ICSA-17-313-02");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_intouch_machine_edition_detect_win.nasl");
  script_mandatory_keys("InTouch/MachineEdition/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

itmVer = "";

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
itmVer = infos['version'];
path = infos['location'];

## Version 8.0 Service Pack 2 Patch 1 == 80.2.1
if(version_is_less_equal(version:itmVer, test_version:"80.2.1"))
{
  report = report_fixed_ver( installed_version:itmVer, fixed_version:"8.1", install_path:path );
  security_message( data:report);
  exit(0);
}
