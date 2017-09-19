###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_livesafe_dos_vuln.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# McAfee LiveSafe Denial of Service Vulnerability
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

CPE = "cpe:/a:mcafee:livesafe";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808082");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2016-4535");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-06-10 13:58:57 +0530 (Fri, 10 Jun 2016)");
  script_name("McAfee LiveSafe Denial of Service Vulnerability");

  script_tag(name:"summary", value:"This host is installed with McAfee LiveSafe
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to the integer signedness
  error in the AV engine before DAT 8145.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to cause a denial of service (memory corruption and crash).

  Impact Level: Application");

  script_tag(name:"affected", value:"McAfee LiveSafe Version 14.0.x");

  script_tag(name:"solution", value:"As a workaround it is recommended to consider 
  one of the following actions, if applicable:
  - Block the network access to the host at the relevant port, by adding an access rule to the appropriate firewall(s).
  - Remove or shutdown the service/product, in case it is not needed.
  - Shield the vulnerability by enabling an IPS signature, if available.
  For updates refer to http://www.mcafee.com/us/");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://bugs.chromium.org/p/project-zero/issues/detail?id=817");
  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/39770");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_mcafee_livesafe_detect.nasl");
  script_mandatory_keys("McAfee/LiveSafe/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
livesafeVer = "";

## Get version
if(!livesafeVer = get_app_version(cpe:CPE)){
  exit(0);
}

livesafeVer = eregmatch( pattern:"^[0-9]+.[0-9]+", string:livesafeVer);
livesafeVer = livesafeVer[0];

if(!livesafeVer){
  exit(0);
}

## Grep for vulnerable version,
if(version_is_equal(version:livesafeVer, test_version:"14.0"))
{
  report = report_fixed_ver(installed_version:livesafeVer, fixed_version:"Workaround");
  security_message(data:report);
  exit(0);
}

