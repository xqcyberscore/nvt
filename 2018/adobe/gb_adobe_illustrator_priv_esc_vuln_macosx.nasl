###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_illustrator_priv_esc_vuln_macosx.nasl 10492 2018-07-12 13:42:55Z santu $
#
# Adobe Illustrator Privilege Escalation Vulnerability-Mac OS X (332644)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813499");
  script_version("$Revision: 10492 $");
  script_cve_id("CVE-2006-0525");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-07-12 15:42:55 +0200 (Thu, 12 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-12 17:09:24 +0530 (Thu, 12 Jul 2018)");
  script_tag(name:"qod", value:"30"); #solution is a patch
  script_name("Adobe Illustrator Privilege Escalation Vulnerability-Mac OS X (332644)");

  script_tag(name: "summary" , value:"The host is installed with Adobe Illustrator
  and is prone to a privilege escalation vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to error in application
  which installs a large number of '.EXE' and '.DLL' files with write-access
  permission for the Everyone group.");

  script_tag(name: "impact" , value:"Successful exploitation will allow local
  users to gain elevated privilege.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Adobe Illustrator CS2 on Mac OS X.");

  script_tag(name: "solution" , value:"Apply patch from vendor. For updates
  refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.adobe.com/support/downloads/detail.jsp?ftpID=3308");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/downloads/detail.jsp?ftpID=3307");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_illustrator_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Illustrator/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
adobeVer = infos['version'];
adobePath = infos['location'];

if(adobeVer =~ "^12\.")
{
  report = report_fixed_ver(installed_version:adobeVer, fixed_version:"Apply Patch", install_path:adobePath);
  security_message(data: report);
  exit(0);
}
exit(0);
