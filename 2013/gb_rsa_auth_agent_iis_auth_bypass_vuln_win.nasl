###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rsa_auth_agent_iis_auth_bypass_vuln_win.nasl 8160 2017-12-18 15:33:57Z cfischer $
#
# RSA Authentication Agent for IIS Authentication Bypass Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:emc:rsa_authentication_agent_iis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804150");
  script_version("$Revision: 8160 $");
  script_cve_id("CVE-2013-3280");
  script_bugtraq_id(63303);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-18 16:33:57 +0100 (Mon, 18 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-11-25 15:39:27 +0530 (Mon, 25 Nov 2013)");
  script_name("RSA Authentication Agent for IIS Authentication Bypass Vulnerability");

  tag_summary = "The host is installed with RSA Authentication Agent for IIS and is prone to
authentication bypass vulnerability.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

 tag_insight = "The flaw is due to fail open design error.";

  tag_impact = "Successful exploitation will allow local attacker to bypass certain security
restrictions and gain unauthorized privileged access.

Impact Level: System/Application";

  tag_affected = "RSA Authentication Agent version 7.1.x before 7.1.2 for IIS.";

  tag_solution = "Upgrade to version 7.1.2 or later,
For updates refer to http://www.rsa.com/node.aspx?id=2575";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/446935.php");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123755");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Oct/att-117/ESA-2013-067.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_rsa_auth_agent_detect_win.nasl");
  script_mandatory_keys("RSA/AuthenticationAgentWebIIS6432/Installed");
  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");
include("host_details.inc");

## Variable Initialization
rsaAutVer = "";

## Get version from KB
rsaAutVer = get_app_version(cpe:CPE);
if(rsaAutVer && rsaAutVer =~ "^7.1")
{
  ## Check for version
  if(version_is_less(version:rsaAutVer, test_version:"7.1.2"))
  {
    security_message(0);
    exit(0);
  }
}
