###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_vrde_priv_esc_vuln_lin.nasl 5612 2017-03-20 10:00:41Z teissa $
#
# Oracle Virtualbox VRDE Privilege Escalation Vulnerability (Linux)
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809079");
  script_version("$Revision: 5612 $");
  script_cve_id("CVE-2016-5605");
  script_bugtraq_id(93685);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-20 11:00:41 +0100 (Mon, 20 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-10-21 14:40:28 +0530 (Fri, 21 Oct 2016)");
  script_name("Oracle Virtualbox VRDE Privilege Escalation Vulnerability (Linux)");

  script_tag(name: "summary" , value:"This host is installed with Oracle VM
  VirtualBox and is prone to a privilege escalation vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to an unspecified error in
  VirtualBox Remote Desktop Extension (VRDE) sub component.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to access and modify data.

  Impact Level: Application");

  script_tag(name: "affected" , value:"VirtualBox versions prior to 5.1.4 on Linux.");

  script_tag(name: "solution" , value:"Upgrade to Oracle VirtualBox version
  5.1.4 or later on Linux. For updates refer to https://www.virtualbox.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
virtualVer = "";

## Get version
if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(virtualVer =~ "^5\.1\.")
{
  ## Grep for vulnerable version
  if(version_is_less(version:virtualVer, test_version:"5.1.4"))
  {
    report = report_fixed_ver(installed_version:virtualVer, fixed_version:"5.1.4");
    security_message(data:report);
    exit(0);
  }
}
