###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_code_exec_vuln_oct17_macosx.nasl 7689 2017-11-08 05:46:44Z teissa $
#
# Microsoft Office Remote Code Execution Vulnerability - Oct17 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:microsoft:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811869");
  script_version("$Revision: 7689 $");
  script_cve_id("CVE-2017-11825");
  script_bugtraq_id(101124);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-08 06:46:44 +0100 (Wed, 08 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-10-17 11:19:59 +0530 (Tue, 17 Oct 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Remote Code Execution Vulnerability - Oct17 (Mac OS X)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2016 on Mac OSX according to Microsoft security
  update October 2017");

  script_tag(name:"vuldetect", value:"Get the installed version with the help 
  of detect nvt and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exist when Microsoft Office fails 
  to properly handle objects in memory. An attacker who successfully exploited 
  the vulnerability could use a specially crafted file to perform actions in 
  the security context of the current user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the currently logged-in 
  user. Failed exploit attempts will likely result in denial of service conditions.

  Impact Level: Application");

  script_tag(name:"affected", value:"Microsoft Office 2016 on Mac OS X");

  script_tag(name:"solution", value:"Apply the patch from below link,
  https://support.office.com/en-gb/article/Release-notes-for-Office-2016-for-Mac-ed2da564-6d53-4542-9954-7e3209681a41");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11825");
  script_xref(name : "URL" , value : "https://support.office.com/en-gb/article/Release-notes-for-Office-2016-for-Mac-ed2da564-6d53-4542-9954-7e3209681a41");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

## Variable Initialization
offVer = "";

## Get the version from KB
if(!offVer = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

## Check for vulnerable version
if(offVer =~ "^(15\.)" && version_is_less(version:offVer, test_version:"15.39"))
{
  report = report_fixed_ver(installed_version:offVer, fixed_version:"15.39.0 (Build 17101000)");
  security_message(data:report);
  exit(0);
}
exit(0);
