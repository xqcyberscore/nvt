###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_mult_rce_vuln_jan17_macosx.nasl 8378 2018-01-11 14:38:57Z gveerendra $
#
# Microsoft Office Multiple Remote Code Execution Vulnerabilities - Jan17 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812729");
  script_version("$Revision: 8378 $");
  script_cve_id("CVE-2018-0792", "CVE-2018-0797", "CVE-2018-0794", "CVE-2018-0793");
  script_bugtraq_id(102381, 102406, 102373, 102375);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-01-11 15:38:57 +0100 (Thu, 11 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-11 14:22:59 +0530 (Thu, 11 Jan 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Multiple Remote Code Execution Vulnerabilities - Jan17 (Mac OS X)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2016 on Mac OSX according to Microsoft security
  update January 2017");

  script_tag(name:"vuldetect", value:"Get the installed version with the help 
  of detect nvt and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Microsoft office software fails to properly handle objects in memory.

  - Microsoft office software fails to properly handle RTF files.

  - Microsoft outlook improperly parses specially crafted email messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code in the context of the current user. If the current user 
  is logged on with administrative user rights, an attacker could take control 
  of the affected system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Office 2016 on Mac OS X");

  script_tag(name:"solution", value:"No solution or patch is available as of
  11th January, 2018. Information regarding this issue will be updated once 
  the solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_xref(name : "URL" , value : "https://support.office.com/en-us/article/Release-notes-for-Office-2016-for-Mac-ed2da564-6d53-4542-9954-7e3209681a41?ui=en-US&rs=en-US&ad=US");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

offVer = "";

if(!offVer = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(offVer =~ "^(15\.)" && version_is_less_equal(version:offVer, test_version:"15.41"))
{
  report = report_fixed_ver(installed_version:offVer, fixed_version:"NoneAvailable");
  security_message(data:report);
  exit(0);
}
exit(0);
