###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_agent_dir_trav_vuln.nasl 6376 2017-06-20 10:00:24Z teissa $
#
# McAfee Agent (MA) Log Viewing Functionality Directory Traversal Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mcafee:mcafee_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806638");
  script_version("$Revision: 6376 $");
  script_cve_id("CVE-2015-7237");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-06-20 12:00:24 +0200 (Tue, 20 Jun 2017) $");
  script_tag(name:"creation_date", value:"2015-12-02 11:14:16 +0530 (Wed, 02 Dec 2015)");
  script_name("McAfee Agent (MA) Log Viewing Functionality Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is installed with McAfee Agent
  and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists in the remote log viewing
  functionality where the inputs passed to the URL are not completely validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to gain access to potentially sensitive information.;

  Impact Level: Application");

  script_tag(name:"affected", value:"McAfee Agent (MA) version 5.x before
  5.0.2");

  script_tag(name:"solution", value:"Upgrade to McAfee Agent (MA) 5.0.2 or later.
  For updates refer to http://www.mcafee.com/us/");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://kc.mcafee.com/corporate/index?page=content&id=SB10130");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_mcafee_agent_detect.nasl");
  script_mandatory_keys("McAfee/Agent/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
agentVer = "";

## Get version
if(!agentVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version,
if(agentVer =~ "^5\.")
{
  ## Check for version less than 5.0.2
  ## https://kc.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/26000/PD26042/en_US/ma_502_rn_en-us.pdf
  if(version_is_less(version:agentVer, test_version:"5.0.2.132"))
  {
    report = 'Installed version: ' + agentVer + '\n' +
             'Fixed version:     5.0.2\n';
    security_message(data:report);
    exit(0);
  }
}
