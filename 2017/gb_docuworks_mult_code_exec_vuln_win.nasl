###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_docuworks_mult_code_exec_vuln_win.nasl 7143 2017-09-15 11:37:02Z santu $
#
# DocuWorks Multiple Code Execution Vulnerabilities (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:fujixerox:docuworks";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811733");
  script_version("$Revision: 7143 $");
  script_cve_id("CVE-2017-10848", "CVE-2017-10849");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-09-15 13:37:02 +0200 (Fri, 15 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-08 15:03:17 +0530 (Fri, 08 Sep 2017)");
  script_name("DocuWorks Multiple Code Execution Vulnerabilities (Windows)");

  script_tag(name: "summary" , value:"The host is installed with DocuWorks and
  is prone to multiple code execution vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws are due to an issue with the
  DLL search path, which may lead to insecurely loading Dynamic Link Libraries.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to gain escalated privileges and run arbitrary code on the affected
  system.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"DocuWorks versions 8.0.7 and earlier.");

  script_tag(name: "solution" , value:"Upgrade to DocuWorks versions 8.0.8 or
  later. For update refer to http://www.fujixerox.co.jp");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://jvn.jp/en/jp/JVN09769017/index.html");
  script_xref(name : "URL" , value : "http://www.fujixerox.co.jp/company/news/notice/2017/0831_rectification_work_2.html");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_docuworks_detect_win.nasl");
  script_mandatory_keys("DocuWorks/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
version = "";
report = "";
fix = "";

## Get the version
if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

## Check the vulnerable version
if(version_is_less(version:version, test_version:"8.0.8"))
{
  report = report_fixed_ver(installed_version:version, fixed_version:"8.0.8");
  security_message(data:report);
  exit(0);
}
exit(0);
