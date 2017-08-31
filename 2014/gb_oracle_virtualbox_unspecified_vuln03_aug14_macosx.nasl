###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_unspecified_vuln03_aug14_macosx.nasl 6735 2017-07-17 09:56:49Z teissa $
#
# Oracle VM VirtualBox Unspecified Vulnerability-03 Aug2014 (Mac OS X)
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804698");
  script_version("$Revision: 6735 $");
  script_cve_id("CVE-2014-4228");
  script_bugtraq_id(68601);
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-17 11:56:49 +0200 (Mon, 17 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-08-04 10:40:13 +0530 (Mon, 04 Aug 2014)");
  script_name("Oracle VM VirtualBox Unspecified Vulnerability-03 Aug2014 (Mac OS X)");

  tag_summary =
"This host is installed with Oracle VM VirtualBox and is prone to unspecified
vulnerability.";

  tag_vuldetect =
"Get the installed version of Oracle VM VirtualBox and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to unspecified error related to the Graphics driver (WDDM) for
Mac OS X guests.";

  tag_impact =
"Successful exploitation will allow local users to affect confidentiality,
integrity, and availability via unknown vectors.

Impact Level: Application";

  tag_affected =
"Oracle VM VirtualBox before versions 4.1.34, 4.2.26, and 4.3.12";

  tag_solution =
"Apply the patch from below link,
http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/59510");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
virtualVer = "";

## Get version
if(!virtualVer = get_app_version(cpe:CPE))
{
  CPE="cpe:/a:sun:virtualbox";
  if(!virtualVer = get_app_version(cpe:CPE))
  {
    error_message(data:"Unable to fetch application version");
    exit(-1);
  }
}

if(virtualVer =~ "^(4\.(1|2|3))")
{
  ## Check for vulnerable version
  if(version_in_range(version:virtualVer, test_version:"4.1.0", test_version2:"4.1.33")||
     version_in_range(version:virtualVer, test_version:"4.2.0", test_version2:"4.2.25")||
     version_in_range(version:virtualVer, test_version:"4.3.0", test_version2:"4.3.11"))
  {
    security_message(0);
    exit(0);
  }
}
