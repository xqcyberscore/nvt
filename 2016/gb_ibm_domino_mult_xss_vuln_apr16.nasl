###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_domino_mult_xss_vuln_apr16.nasl 5588 2017-03-16 10:00:36Z teissa $
#
# IBM Domino Multiple Cross-site Scripting Vulnerabilities - Apr16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807649");
  script_version("$Revision: 5588 $");
  script_cve_id("CVE-2015-2014", "CVE-2015-2015");
  script_bugtraq_id(76373, 76376);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-16 11:00:36 +0100 (Thu, 16 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-04-06 16:24:52 +0530 (Wed, 06 Apr 2016)");
  script_name("IBM Domino Multiple Cross-site Scripting Vulnerabilities - Apr16");

  script_tag(name:"summary", value:"This host is installed with IBM Domino and
  is prone to multiple cross-site scripting vulnerabilities");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The multiple flaws are due to an improper
  validation of user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute script in a victim's Web browser within the security context of
  the hosting Web site, once the URL is clicked. 

  Impact Level: System/Application");

  script_tag(name:"affected", value:"IBM Domino 8.5 before 8.5.3 FP6 IF9 and 
  and 9.0 before 9.0.1 FP4.");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 IF9 or
  9.0.1 FP4 or later.
  For more information refer to,
  http://www-01.ibm.com/support/docview.wss?uid=swg21663023");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21963016");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_lotus_domino_detect.nasl");
  script_mandatory_keys("Domino/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
domVer = "";
domPort = "";

# get the port
if(!domPort = get_app_port(cpe:CPE)){
  exit(0);
}

# get the version
if(!domVer = get_app_version(cpe:CPE, port:domPort)){
  exit(0);
}

domVer1 = ereg_replace(pattern:"FP", string:domVer, replace: ".");

if(version_in_range(version:domVer1, test_version:"8.5", test_version2:"8.5.3.6"))
{
  fix = "8.5.3 FP6 IF9";
  VULN = TRUE;
}

if(version_in_range(version:domVer1, test_version:"9.0.0", test_version2:"9.0.1.3"))
{
  fix = "9.0.1 FP4";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:domVer, fixed_version:fix);
  security_message(data:report, port:domPort);
  exit(0);
}
