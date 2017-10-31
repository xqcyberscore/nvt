###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xnview_jb2_file_dos_vuln.nasl 7588 2017-10-27 06:53:29Z santu $
#
# XnView 'jb2 file' DoS Vulnerability
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

CPE = "cpe:/a:xnview:xnview";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811952");
  script_version("$Revision: 7588 $");
  script_cve_id("CVE-2017-14580");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-27 08:53:29 +0200 (Fri, 27 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-26 10:35:33 +0530 (Thu, 26 Oct 2017)");
  script_name("XnView 'jb2 file' DoS Vulnerability");

  script_tag(name: "summary" , value:"This host is installed with XnView and is
  prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of the detection NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to an improper handling
  of crafted '.jb2' file."); 

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to to execute arbitrary code or cause a denial of service.

  Impact Level: Application");

  script_tag(name: "affected" , value:"XnView Version 2.41");

  script_tag(name: "solution" , value:"No solution or patch is available as of
  26th Oct, 2017. Information regarding this issue will be updated once the
  solution details are available.
  For updates refer to http://www.xnview.com/en/");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-14580");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");
  exit(0);
}


# Code starts from here

include("version_func.inc");
include("host_details.inc");

xnVer = "";
if(!xnVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check version
if(version_is_equal(version:xnVer, test_version:"2.41"))
{
  report = report_fixed_ver(installed_version:xnVer, fixed_version:"NoneAvailable");
  security_message(data:report);
  exit(0);
}
