###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-048.nasl 6735 2017-07-17 09:56:49Z teissa $
#
# Microsoft OneNote Remote Code Execution Vulnerability (2977201)
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

CPE = "cpe:/a:microsoft:onenote";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804809");
  script_version("$Revision: 6735 $");
  script_cve_id("CVE-2014-2815");
  script_bugtraq_id(69098);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-17 11:56:49 +0200 (Mon, 17 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-08-13 13:20:09 +0530 (Wed, 13 Aug 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("Microsoft OneNote Remote Code Execution Vulnerability (2977201)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS14-048";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to an unspecified error.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code and
compromise a user's system.

Impact Level: System";

  tag_affected =
"Microsoft OneNote 2007 Service Pack 3";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-048";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2982791");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2976897");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS14-048");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_onenote_detect.nasl");
  script_mandatory_keys("MS/Office/OneNote/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

# Variable Initialization
noteVer ="";

## Get 'OneNote.exe' Version
noteVer = get_app_version(cpe:CPE);

if(noteVer && noteVer =~ "^12.*")
{
  ## Grep for version 'Onenote.exe' 12 < 12.0.6650.5000,
  if(version_in_range(version:noteVer, test_version:"12.0", test_version2:"12.0.6650.4999"))
  {
    security_message(0);
    exit(0);
  }
}
