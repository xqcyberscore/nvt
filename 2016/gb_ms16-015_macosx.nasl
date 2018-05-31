###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-015_macosx.nasl 10029 2018-05-30 13:29:18Z santu $
#
# Microsoft Office Remote Code Execution Vulnerabilities-3134226(Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807081");
  script_version("$Revision: 10029 $");
  script_cve_id("CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0054");
  script_bugtraq_id(82508, 82652, 82654);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 15:29:18 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2016-03-01 14:45:35 +0530 (Tue, 01 Mar 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities-3134226(Mac OS X)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-015");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple memory
  corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers  to execute arbitrary code in the context of the currently 
  logged-in user. Failed exploit attempts will likely result in denial of 
  service conditions.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Office 2011 on Mac OS X");

  script_tag(name:"solution", value:"Apply the patch from below link,
  https://technet.microsoft.com/library/security/MS16-015");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3137721");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-015");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}


include("version_func.inc");

offVer = get_kb_item("MS/Office/MacOSX/Ver");

if(offVer && offVer =~ "^(14\.1)")
{
  if(version_is_less(version:offVer, test_version:"14.6.1"))
  {
    report = 'File version:     ' + offVer   + '\n' +
             'Vulnerable range: 14.1.0 - 14.6.0 ' + '\n' ;
    security_message(data:report);
  }
}
exit(99);
