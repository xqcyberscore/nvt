###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_baidu_spark_browser_dos_vuln_aug14_win.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Baidu Spark Browser Denial of Service Vulnerability -01 August14 (Windows)
#
# Authors:
# Deepmala <kdeepmala@secpod.com>
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

CPE = "cpe:/a:baidu:spark_browser";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804901");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2014-5349");
  script_bugtraq_id(68288);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2014-08-26 10:44:09 +0530 (Tue, 26 Aug 2014)");
  script_name("Baidu Spark Browser Denial of Service Vulnerability -01 August14 (Windows)");

  tag_summary =
"This host is installed with Baidu Spark Browser and is prone to denial of
service vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw exists in the window.print JavaScript function when exceptional
conditions are not handled properly.";

  tag_impact =
"Successful exploitation will allow remote attackers to cause a denial of service
conditions resulting in stack overflow via nested calls to the window.print
javascript function.

Impact Level: Application";

  tag_affected =
"Baidu Spark Browser 26.5.9999.3511 on Windows.";

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
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/33951");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2014070013");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/127282");
  script_xref(name : "URL" , value : "http://www.vfocus.net/art/20140701/11614.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_baidu_spark_browser_detect_win.nasl");
  script_mandatory_keys("BaiduSparkBrowser/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
baiduVer = "";

## Get the Baidu spark Browser version
baiduVer = get_app_version(cpe:CPE);
if(!baiduVer){
  exit(0);
}

## Check for Baidu spark Browser version = 26.5.9999.3511
if(version_is_equal(version:baiduVer, test_version: "26.5.9999.3511"))
{
  security_message(0);
  exit(0);
}
