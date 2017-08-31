###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_opensso_mult_xss_vuln.nasl 6759 2017-07-19 09:56:33Z teissa $
#
# Oracle OpenSSO Multiple XSS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804436";
CPE = "cpe:/a:oracle:opensso";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6759 $");
  script_bugtraq_id(56733);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-22 13:06:41 +0530 (Tue, 22 Apr 2014)");
  script_name("Oracle OpenSSO Multiple XSS Vulnerabilities");

  tag_summary =
"This host is running Oracle OpenSSO and is prone to multiple cross-site
scripting vulnerabilities.";

  tag_vuldetect =
"Get the installed version of Oracle OpenSSO with the help of detect NVT
and check the version is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to an,
 - Improper validation of 'dob_Day', 'dog_Month', 'dog_Year', 'givenname',
   'name', and 'sn' parameters upon submission to the cmp_generate_tmp_pw.tiles
   script.
 - Improper validation of 'dob_day', 'dob_Month', 'dob_Year', 'givenname',
   'mail', 'sn', 'x', and 'y' parameters upon submission to UI/Login in
   the ResetPassword module. ";

  tag_impact =
"Successful exploitation will allow attackers to create a specially crafted
request that would execute arbitrary script code in a user's browser within
the trust relationship between their browser and the server.

Impact Level: Application";

  tag_affected =
"Oracle OpenSSO 8.0 Update 2 Patch3 Build 6.1";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/23004");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80368");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2012110221");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5114.php");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_sun_opensso_detect.nasl");
  script_mandatory_keys("Oracle/OpenSSO/installed");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable initialization
ooPort = "";
ooVer = "";

## Get Application HTTP Port
if(!ooPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get application version
ooVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:ooPort);
if(!ooVer){
  exit(0);
}

if(version_is_equal(version:ooVer, test_version:"8.0"))
{
  security_message(port:ooPort);
  exit(0);
}
