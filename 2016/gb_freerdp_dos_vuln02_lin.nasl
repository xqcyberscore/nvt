###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freerdp_dos_vuln02_lin.nasl 4744 2016-12-12 12:02:31Z cfi $
#
# FreeRDP Denial of Service Vulnerability-02 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
CPE = "cpe:/a:freerdp_project:freerdp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809739");
  script_version("$Revision: 4744 $");
  script_cve_id("CVE-2013-4119");
  script_bugtraq_id(61072);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-12-12 13:02:31 +0100 (Mon, 12 Dec 2016) $");
  script_tag(name:"creation_date", value:"2016-12-01 17:47:04 +0530 (Thu, 01 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_name("FreeRDP Denial of Service Vulnerability-02 (Linux)");
  script_tag(name: "summary" , value:"The host is installed with FreeRDP and is
  prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to NULL pointer
  dereference error within the application.");

  script_tag(name: "impact" , value:"Successful exploitation will allow a remote
  attackers to cause a denial of service condition.

  Impact Level: Application");

  script_tag(name: "affected" , value:"FreeRDP version before 1.1.0-beta+2013071101
  on Linux.");

  script_tag(name: "solution" , value:"Upgrade to FreeRDP 1.1.0-beta+2013071101
  or later. For updates refer to http://www.freerdp.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2013/07/12/2");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2013/07/11/12");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");
  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

## Variable Initialization
installVer = "";
report = "";

## Get version
if(!installVer = get_app_version(cpe:CPE)){
  exit(0);
}

##Using revcomp to compare package version precisely
if(revcomp(a:installVer, b: "1.1.0-beta+2013071101") < 0)
{
  report = report_fixed_ver(installed_version: installVer, fixed_version: "1.1.0-beta+2013071101");
  security_message(data: report);
  exit(0);
}
exit(0);
