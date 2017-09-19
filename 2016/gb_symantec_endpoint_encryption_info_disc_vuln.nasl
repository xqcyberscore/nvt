###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_endpoint_encryption_info_disc_vuln.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Symantec Endpoint Encryption Client Memory Dump Information Disclosure Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE= "cpe:/a:symantec:endpoint_encryption";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808071");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2015-6556");
  script_tag(name:"cvss_base", value:"2.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-06-07 13:17:49 +0530 (Tue, 07 Jun 2016)");
  script_name("Symantec Endpoint Encryption Client Memory Dump Information Disclosure Vulnerability");

  script_tag(name: "summary" , value: "This host is installed with Symantec
  Endpoint Encryption (SEE) and is prone to information disclosure
  vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaw exists due to an access to a memory
  dump of 'EACommunicatorSrv.exe' in the Framework Service.");

  script_tag(name: "impact" , value: "Successful exploitation will allow remote
  authenticated users to discover credentials by triggering a memory dump.

  Impact Level: Application.");

  script_tag(name: "affected" , value:"Symantec Endpoint Encryption (SEE) version
  prior to 11.1.0.");

  script_tag(name: "solution" , value:"Update to Symantec Endpoint Encryption (SEE)
  version 11.1.0 or later. For updates refer to http://www.symantec.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name: "URL" , value : "https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20151214_00");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_endpoint_encryption_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Encryption/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
seeVer= "";

## Get version
if(!seeVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check vulnerable versions
if(version_is_less(version:seeVer, test_version:"11.1.0"))
{
  report = report_fixed_ver(installed_version:seeVer, fixed_version: "11.1.0");
  security_message(data:report);
  exit(0);
}
