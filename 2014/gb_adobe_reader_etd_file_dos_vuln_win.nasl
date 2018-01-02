###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_etd_file_dos_vuln_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Reader '.ETD File' Denial of Service Vulnerability (Windows)
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804384");
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-2004-1153");
  script_bugtraq_id(11934);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-04-10 15:10:46 +0530 (Thu, 10 Apr 2014)");
  script_name("Adobe Reader '.ETD File' Denial of Service Vulnerability (Windows)");

  tag_summary = "This host is installed with Adobe Reader and is prone to denial of service
vulnerability.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight = "Flaw is due to the format string error in '.etd' file.";

  tag_impact = "Successful exploitation will allow attackers to execute arbitrary code on
the system and gain sensitive information.

Impact Level: System/Application";

  tag_affected = "Adobe Reader version 6.0.0 through 6.0.2 on Windows.";

  tag_solution = "Upgrade to Adobe Reader version 6.0.3 or later. For updates refer to
http://get.adobe.com/reader";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/18478");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2004-12/0147.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer)
{
  ## Check Adobe Reader version,6.0.1==006.000.001
  if(version_in_range(version:readerVer, test_version:"6.0.0", test_version2:"6.0.2"))
  {
    security_message(0);
    exit(0);
  }
}
