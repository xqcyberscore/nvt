###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_unspecified_vuln_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Reader Unspecified Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802165");
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-2011-1353");
  script_bugtraq_id(49586);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)");
  script_name("Adobe Reader Unspecified Vulnerability (Windows)");

  tag_summary = "This host is installed with Adobe Reader and is prone to unspecified
vulnerability.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version is
vulnerable or not.";

  tag_insight = "An unspecified flaw is present in the application which can be exploited
through unknown attack vectors.";

  tag_impact = "Successful exploitation will let attackers to gain privileges via unknown
vectors.

Impact Level: Application";

  tag_affected = "Adobe Reader version 10.x through 10.1 on Windows";

  tag_solution = "Upgrade to Adobe Reader version 10.1.1 or later.
For updates refer to http://www.adobe.com";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-24.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# Check for Adobe Reader
if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer =~ "^10")
{
  # Check for Adobe Reader version
  if(version_in_range(version:readerVer, test_version:"10.0", test_version2:"10.1"))
  {
    security_message(0);
    exit(0);
  }
}
