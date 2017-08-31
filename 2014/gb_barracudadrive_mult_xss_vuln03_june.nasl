###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_barracudadrive_mult_xss_vuln03_june.nasl 6724 2017-07-14 09:57:17Z teissa $
#
# BarracudaDrive Multiple XSS Vulnerabilities -03 June14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:barracudadrive:barracudadrive";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804612");
  script_version("$Revision: 6724 $");
  script_cve_id("CVE-2014-3807", "CVE-2014-4335");
  script_bugtraq_id(67428, 68079);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-14 11:57:17 +0200 (Fri, 14 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-06-02 13:48:59 +0530 (Mon, 02 Jun 2014)");
  script_name("BarracudaDrive Multiple XSS Vulnerabilities -03 June14");

 tag_summary =
"This host is running BarracudaDrive and is prone to multiple XSS
vulnerabilities.";

 tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws exist as,
- Input passed via the 'blog' parameter to 'private/manage/', 'bloggeruser'
parameter to 'private/manage/', Input passed via the 'bloggerpasswd'
parameter to 'private/manage/', Input passed via the 'host' and 'password'
parameters is not  properly verified before it is given to server for
processing.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary
HTML and script code in a user's browser session in the context of a
vulnerable site.

Impact Level: Application";

  tag_affected =
"BarracudaDrive version 6.7.2";

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

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/93899");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/126645");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/127128");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_barracuda_drive_detect.nasl");
  script_mandatory_keys("BarracudaDrive/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
bdVer = "";
bdPort = "";

## Get Application HTTP Port
if(!bdPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get application version
bdVer = get_app_version(cpe:CPE, port:bdPort);
if(!bdVer){
  exit(0);
}

## Check barracuda version
if(version_is_equal(version:bdVer, test_version:"6.7.2"))
{
  security_message(bdPort);
  exit(0);
}
