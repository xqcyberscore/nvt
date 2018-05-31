###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_ms16-107_macosx.nasl 10029 2018-05-30 13:29:18Z santu $
#
# Microsoft Office Multiple Remote Code Execution Vulnerabilities-3185852(Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:microsoft:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807367");
  script_version("$Revision: 10029 $");
  script_cve_id("CVE-2016-0141", "CVE-2016-3357");
  script_bugtraq_id(92903, 92786);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 15:29:18 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2016-09-14 14:45:19 +0530 (Wed, 14 Sep 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Multiple Remote Code Execution Vulnerabilities-3185852(Mac OS X)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-107");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaws exists as office software
  fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers  to run arbitrary code in the context of the current user.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"
  Microsoft Office 2011 on Mac OS X");

  script_tag(name:"solution", value:"Apply the patch from below link,
  https://technet.microsoft.com/library/security/MS16-107");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3186807");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3186805");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-107");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}


include("version_func.inc");

if(!offVer = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(offVer && offVer =~ "^(14\.)")
{
  if(version_is_less(version:offVer, test_version:"14.6.7"))
  { 
    report = 'File version:     ' + offVer   + '\n' +
             'Vulnerable range: 14.1.0 - 14.6.7 ' + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

if(offVer =~ "^(15\.)" && version_is_less(version:offVer, test_version:"15.25.0"))
{
  report = 'File version:     ' + offVer   + '\n' +
           'Vulnerable range: 15.0 - 15.25.0 ' + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
