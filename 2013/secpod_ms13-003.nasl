###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-003.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# MS System Center Operations Manager XSS Vulnerabilities (2748552)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to insert script code
  or issue commands to the SCOM server , which will be executed in a user's
  browser session in the context of an affected site.
  Impact Level: Application";

tag_affected = "Microsoft System Center Operations Manager 2007 R2
  Microsoft System Center Operations Manager 2007 SP1";
tag_insight = "Input validation error due the way System Center Operations Manager
  handles specially crafted requests, which can be exploited to insert
  arbitrary HTML and script code.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-003";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-003.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903100");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-0009", "CVE-2013-0010");
  script_bugtraq_id(55408, 55401);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-01-09 10:25:58 +0530 (Wed, 09 Jan 2013)");
  script_name("MS System Center Operations Manager XSS Vulnerabilities (2748552)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51686/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/78069");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/78070");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-003");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_scom_detect_win.nasl");
  script_mandatory_keys("MS/SCOM/Ver", "MS/SCOM/Path");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

## Variables Initialization
key = "";
version = "";
exeVer = "";
exchangePath = "";

## Check for Microsoft System Center Operations Manager 2007
scom_name = get_kb_item("MS/SCOM/Ver");
if(!scom_name) exit(0);

if("System Center Operations Manager 2007" >< scom_name)
{
  scom_path = get_kb_item("MS/SCOM/Path");
  if(scom_path && "Could not find the install Location" >!< scom_path)
  {
    scom_exeVer = fetch_file_version(sysPath: scom_path, file_name:"Microsoft.Mom.ConfigServiceHost.exe");
    if(scom_exeVer)
    {
      if(version_in_range(version:scom_exeVer, test_version:"6.0.5000.0", test_version2:"6.0.6278.0")||
         version_in_range(version:scom_exeVer, test_version:"6.1.7221.0", test_version2:"6.1.7221.109"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
