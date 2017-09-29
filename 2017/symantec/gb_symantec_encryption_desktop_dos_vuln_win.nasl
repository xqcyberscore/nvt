###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_encryption_desktop_dos_vuln_win.nasl 7318 2017-09-29 05:31:27Z asteins $
#
# Symantec Encryption Desktop Denial-of-Service Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:symantec:encryption_desktop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811786");
  script_version("$Revision: 7318 $");
  script_cve_id("CVE-2017-6330");
  script_bugtraq_id(100552);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-09-29 07:31:27 +0200 (Fri, 29 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-22 11:53:27 +0530 (Fri, 22 Sep 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Symantec Encryption Desktop Denial-of-Service Vulnerability (Windows)");

  script_tag(name: "summary" , value:"The host is installed with Symantec
  Encryption Desktop and is prone to denial-of-service vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to some unspecified error
  within the application.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attacker
  to cause denial-of-service conditions.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Symantec Encryption Desktop prior to
  version 10.4.1MP2.");

  script_tag(name: "solution" , value:"Upgrade to Symantec Encryption Desktop
  version 10.4.1MP2 or later. For updates refer to https://www.symantec.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20170907_00");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_pgp_desktop_detect_win.nasl");
  script_mandatory_keys("PGPDesktop_or_EncryptionDesktop/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
symanVer = "";

## Get version
if(!symanVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
## 10.4.1MP2 == 10.4.1.759
if(version_is_less(version:symanVer, test_version:"10.4.1.7591"))
{
  report = report_fixed_ver(installed_version:symanVer, fixed_version:"10.4.1MP2");
  security_message(data:report);
  exit(0);
}
exit(0);
