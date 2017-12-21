###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_iprint_client_dos_vuln_feb14_win.nasl 8201 2017-12-20 14:28:50Z cfischer $
#
# Novell iPrint Client Denial of Service (dos) Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:novell:iprint";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804308");
  script_version("$Revision: 8201 $");
  script_cve_id("CVE-2013-3708");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 15:28:50 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-02-05 21:04:07 +0530 (Wed, 05 Feb 2014)");
  script_name("Novell iPrint Client Denial of Service (dos) Vulnerability (Windows)");

  tag_summary = "The host is installed with Novell iPrint Client and is prone to
denial-of-service vulnerability.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight = "The flaw is due to some unspecified error in 'id1.GetPrinterURLList(arg1,arg2)'
function.";

  tag_impact = "Successful exploitation will allow remote attackers to conduct denial of
service.

Impact Level: Application";

  tag_affected = "Novell iPrint Client before version 5.93 on Windows.";

  tag_solution = "Upgrade to version 5.93 or later,
For updates refer to http://www.novell.com";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.novell.com/support/kb/doc.php?id=7014184");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/iPrint/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
novVer = "";

## Get version
if(!novVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:novVer, test_version:"5.93"))
{
  security_message(0);
  exit(0);
}
