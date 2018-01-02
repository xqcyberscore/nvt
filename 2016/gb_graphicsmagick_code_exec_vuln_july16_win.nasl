###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_graphicsmagick_code_exec_vuln_july16_win.nasl 8209 2017-12-21 08:12:18Z cfischer $
#
# GraphicsMagick Code Execution And Denial of Service Vulnerabilities July16 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808248");
  script_version("$Revision: 8209 $");
  script_cve_id("CVE-2016-5118", "CVE-2016-5241", "CVE-2016-5240");
  script_bugtraq_id(90938, 89348);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 09:12:18 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-07-07 14:17:08 +0530 (Thu, 07 Jul 2016)");
  script_name("GraphicsMagick Code Execution And Denial of Service Vulnerabilities July16 (Windows)");

  script_tag(name: "summary" , value:"This host is installed with GraphicsMagick
  and is prone to arbitrary code execution and denial of service vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the
  help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws are due to, 
  - The'OpenBlob' function in blob.c script does not validate 'filename' string.
  - An arithmetic exception error in script magick/render.c while converting a svg 
    file.
  - The 'DrawDashPolygon' function in 'magick/render.c' script detect and reject
    negative stroke-dasharray arguments which were resulting in endless looping.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to execute arbitrary commands and cause a denial of service
  on the target system.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"GraphicsMagick version before 1.3.24
  on Windows");

  script_tag(name: "solution" , value: "Upgrade to GraphicsMagick version 1.3.24 
  or later. For updates refer to http://www.graphicsmagick.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1035985");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2016/05/30/1");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2016/q2/460");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=1333410");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2016/09/18/8");
  script_xref(name : "URL" , value : "http://hg.graphicsmagick.org/hg/GraphicsMagick/raw-rev/ddc999ec896c");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("GraphicsMagick/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
gmVer = "";

## Get the version
if(!gmVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check the version is before 1.3.24
if(version_is_less(version:gmVer, test_version:"1.3.24"))
{
  report = report_fixed_ver(installed_version:gmVer, fixed_version:"1.3.24");
  security_message(data:report);
  exit(0);
}
