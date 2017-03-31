###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-054_macosx.nasl 4564 2016-11-18 09:09:19Z antu123 $
#
# Microsoft Office Remote Code Execution Vulnerability-3155544(Mac OS X)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807328");
  script_version("$Revision: 4564 $");
  script_cve_id("CVE-2016-0198");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-11-18 10:09:19 +0100 (Fri, 18 Nov 2016) $");
  script_tag(name:"creation_date", value:"2016-05-11 16:02:03 +0530 (Wed, 11 May 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Remote Code Execution Vulnerability-3155544(Mac OS X)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-054");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw is due to multiple memory corruption
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the currently 
  logged-in user and could take control of the affected system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Office 2011 on Mac OS X");

  script_tag(name:"solution", value:"Apply the patch from below link,
  https://technet.microsoft.com/library/security/MS16-054");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-in/kb/3155777");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-054");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
offVer = "";

## Get the version from KB
offVer = get_kb_item("MS/Office/MacOSX/Ver");

## check the version from KB
if(!offVer || !(offVer =~ "^(14\.)")){
  exit(0);
}

## Check for Office Version < (14.6.4)
if(version_in_range(version:offVer, test_version:"14.1.0", test_version2:"14.6.3"))
{
  report = 'File version:     ' + offVer   + '\n' +
           'Vulnerable range: 14.1.0 - 14.6.3 ' + '\n' ;
  security_message(data:report);
}
