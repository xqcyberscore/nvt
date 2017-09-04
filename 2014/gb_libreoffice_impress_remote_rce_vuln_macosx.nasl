###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libreoffice_impress_remote_rce_vuln_macosx.nasl 6995 2017-08-23 11:52:03Z teissa $
#
# LibreOffice Impress Remote Socket Manager RCE Vulnerability Nov14 (Mac OS X)
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

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804886");
  script_version("$Revision: 6995 $");
  script_cve_id("CVE-2014-3693");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-08-23 13:52:03 +0200 (Wed, 23 Aug 2017) $");
  script_tag(name:"creation_date", value:"2014-11-19 15:18:35 +0530 (Wed, 19 Nov 2014)");
  script_name("LibreOffice Impress Remote Socket Manager RCE Vulnerability Nov14 (Mac OS X)");

  script_tag(name: "summary" , value:"This host is installed with LibreOffice
  and is prone to remote code execution vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Flaw exists due to use-after-free error
  in the Impress Remote socket manager.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers
  to cause a denial of service (crash) or possibly execute arbitrary code.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"LibreOffice version 4.x prior
  to 4.2.7 and 4.3.x prior to 4.3.3 on Mac OS X");

  script_tag(name: "solution" , value:"Upgrade to LibreOffice 4.2.7 or 4.3.3
  or later, For updates refer to http://www.libreoffice.org");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://secunia.com/advisories/62132");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/CVE-2014-3693");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_libreoffice_detect_macosx.nasl");
  script_mandatory_keys("LibreOffice/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
libreVer = "";

## Get version
if(!libreVer = get_app_version(cpe:CPE)){
  exit(0);
}

##Check for version 4.x lass than 4.2.7
if(libreVer =~ "^(4\.)")
{
  ## Check for vulnerable version
  if(version_is_less(version:libreVer, test_version:"4.2.7"))
  {
    security_message(0);
  }
}

## Check for version 4.3.x less than 4.3.3
if(libreVer =~ "^(4\.3)")
{
  ## Check for vulnerable version
  if(version_is_less(version:libreVer, test_version:"4.3.3"))
  {
    security_message(0);
    exit(0);
  }
}
