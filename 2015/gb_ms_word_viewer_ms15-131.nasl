###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_word_viewer_ms15-131.nasl 6551 2017-07-06 09:58:21Z teissa $
#
# Microsoft Office Word Viewer Remote Code Execution Vulnerability (3116111)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806175");
  script_version("$Revision: 6551 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 11:58:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-12-09 13:05:09 +0530 (Wed, 09 Dec 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Word Viewer Remote Code Execution Vulnerability (3116111)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-131.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Flaws are due to improper handling of files
  in the memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and
  to perform actions in the security context of the current user.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Word Viewer");

  script_tag(name:"solution", value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  below link, https://technet.microsoft.com/en-us/security/bulletin/ms15-131");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3114479");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/library/security/MS15-131");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/WordView/Version");
  exit(0);
}


include("version_func.inc");

## Variable Initailization
wordviewVer = "";

wordviewVer = get_kb_item("SMB/Office/WordView/Version");
if(wordviewVer)
{
  ## Check for Wordview.exe 11.0 <  11.0.8422
  if(version_in_range(version:wordviewVer, test_version:"11.0", test_version2:"11.0.8421"))
  {
     report = 'File checked:     Wordview.exe' + '\n' +
              'File version:     ' + wordviewVer + '\n' +
              'Vulnerable range: 11.0 - 11.0.8421 \n' ;
     security_message(data:report);
     exit(0);
  }
}
