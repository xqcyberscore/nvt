###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_irfanview_mult_dos_vuln_oct17.nasl 7597 2017-10-27 12:23:39Z asteins $
#
# IrfanView Multiple DoS Vulnerabilities Oct17
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:irfanview:irfanview";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811954");
  script_version("$Revision: 7597 $");
  script_cve_id("CVE-2017-14540", "CVE-2017-14539", "CVE-2017-14693");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-27 14:23:39 +0200 (Fri, 27 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-26 11:40:33 +0530 (Thu, 26 Oct 2017)");
  script_name("IrfanView Multiple DoS Vulnerabilities Oct17");

  script_tag(name: "summary" , value:"This host is installed with IrfanView and is
  prone to multiple denial of service vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of the detection NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exits due to
  data from faulting address controls branch selection starts at
  particular point.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to to execute arbitrary code or cause a denial of service.

  Impact Level: Application");

  script_tag(name: "affected" , value:"IrfanView Version 4.44 32bit version only");

  script_tag(name: "solution" , value:"No solution or patch is available as of
  26th Oct, 2017. Information regarding this issue will be updated once the
  solution details are available.
  For updates refer to http://www.irfanview.com/");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "https://github.com/wlinzi/security_advisories");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_irfanview_detect.nasl");
  script_mandatory_keys("IrfanView/Ver");
  script_exclude_keys("IrfanView/Ver/x64");
  exit(0);
}


# Code starts from here

include("version_func.inc");
include("host_details.inc");

irfVer = "";
if(!irfVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check version
if(version_is_equal(version:irfVer, test_version:"4.44"))
{
  report = report_fixed_ver(installed_version:irfVer, fixed_version:"NoneAvailable");
  security_message(data:report);
  exit(0);
}
