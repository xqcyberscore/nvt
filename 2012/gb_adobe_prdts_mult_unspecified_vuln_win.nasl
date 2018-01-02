###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_unspecified_vuln_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Reader Multiple Unspecified Vulnerabilities - Windows
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802954");
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-2012-4363");
  script_bugtraq_id(55055);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-08-24 16:05:37 +0530 (Fri, 24 Aug 2012)");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities - Windows");

  tag_summary = "This host is installed with Adobe Reader and is prone to multiple unspecified
vulnerabilities.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight = "The flaws are due to an unspecified errors.";

  tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in the
context of the affected application.

Impact Level: System/Application";

  tag_affected = "Adobe Reader versions 9.x to 9.5.2 and 10.x to 10.1.4 on Windows";

  tag_solution = "Upgrade to Adobe Reader 9.5.3, 10.1.5 or later,
For updates refer to http://www.adobe.com";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/50290");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

function version_check(ver)
{
  if(version_is_less(version:ver, test_version:"9.5.3") ||
     version_in_range(version:ver, test_version:"10.0", test_version2:"10.1.4"))
  {
    security_message(0);
    exit(0);
  }
}

if(readerVer = get_app_version(cpe:CPE)){
  version_check(ver:readerVer);
}
