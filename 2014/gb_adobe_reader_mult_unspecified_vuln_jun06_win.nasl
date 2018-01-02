###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_unspecified_vuln_jun06_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Reader Multiple Unspecified Vulnerabilities Jun06 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804390");
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-2006-3093");
  script_bugtraq_id(18445);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-04-11 13:14:20 +0530 (Fri, 11 Apr 2014)");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities Jun06 (Windows)");

  tag_summary = "This host is installed with Adobe Reader and is prone to multiple unspecified
vulnerabilities.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight = "Flaws exist due to some unspecified errors.";

  tag_impact = "Successful exploitation will allow attackers to have unspecified impact.

Impact Level: Application";

  tag_affected = "Adobe Reader before version 7.0.8 on Windows.";

  tag_solution = "Upgrade to Adobe Reader version 7.0.8 or later. For updates refer to
http://get.adobe.com/reader";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/20576");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1016314");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/31829");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/techdocs/327817.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
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
  ## Check Adobe Reader version < 7.0.8
  if(version_is_less(version:readerVer, test_version:"7.0.8"))
  {
    security_message(0);
    exit(0);
  }
}
