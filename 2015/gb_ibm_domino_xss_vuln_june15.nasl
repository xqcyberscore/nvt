###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_domino_xss_vuln_june15.nasl 7575 2017-10-26 09:47:04Z cfischer $
#
# IBM Domino Cross-Site Scripting Vulnerability - June15
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805579");
  script_version("$Revision: 7575 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:47:04 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2015-06-02 11:37:07 +0530 (Tue, 02 Jun 2015)");
  script_name("IBM Domino Cross-Site Scripting Vulnerability - June15");

  script_tag(name:"summary", value:"This host is installed with IBM Domino and
  is prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to insufficient authentication
  and insufficient brute force measures.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.

  Impact Level: Application");

  script_tag(name:"affected", value:"IBM Domino 8.5.x through 8.5.4
  and 9.x through 9.0.1");

  script_tag(name:"solution", value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://securityvulns.ru/docs29277.html");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2015/May/128");
  script_xref(name : "URL" , value : "http://www.zdnet.com/article/xss-flaw-exposed-in-ibm-domino-enterprise-platform");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_lotus_domino_detect.nasl");
  script_mandatory_keys("Domino/Version");
  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc"); # Used in get_highest_app_version
include("host_details.inc");

## Variable Initialization
domVer = "";

if(!domVer = get_highest_app_version(cpe:CPE)){
  exit(0);
}

##Remove Fix Pack if present
domVer1 = ereg_replace(pattern:"FP[0-9.]+", string:domVer, replace: "");

if(domVer1)
{
  if(version_in_range(version:domVer1, test_version:"8.5", test_version2:"8.5.4")||
     version_in_range(version:domVer1, test_version:"9.0", test_version2:"9.0.1"))
  {
    report = 'Installed Version: ' + domVer + '\nFixed Version: WillNotFix' + '\n';
    security_message(data:report, port:0);
    exit(0);
  }
}
