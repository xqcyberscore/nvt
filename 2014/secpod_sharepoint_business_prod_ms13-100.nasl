###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sharepoint_business_prod_ms13-100.nasl 9319 2018-04-05 08:03:12Z cfischer $
#
# Microsoft SharePoint Business Productivity Server RCE Vulnerability (2904244)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903332");
  script_version("$Revision: 9319 $");
  script_cve_id("CVE-2013-5059");
  script_bugtraq_id(64081);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 10:03:12 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-01-09 12:53:16 +0530 (Thu, 09 Jan 2014)");
  script_name("Microsoft SharePoint Business Productivity Server RCE Vulnerability (2904244)");

  tag_summary = "This host is missing an important security update according to Microsoft
Bulletin MS13-100.";

  tag_vuldetect = "Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight = "Flaws is due to some input sanitisation errors related to SharePoint content";

  tag_impact = "Successful exploitation will allow attackers to execute arbitrary code with
the privileges of the W3WP service account.

Impact Level: Application";

  tag_affected = "Microsoft Business Productivity Servers on,

- Microsoft SharePoint Server 2010 Service Pack 1

- Microsoft SharePoint Server 2010 Service Pack 2

- Microsoft SharePoint 2013";

  tag_solution = "Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
http://technet.microsoft.com/en-us/security/bulletin/ms13-100";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/55985");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS13-100");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
shareVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## SharePoint Server 2010
if(shareVer =~ "^14\..*")
{
  path = path + "\14.0\Bin";

  dllVer = fetch_file_version(sysPath:path, file_name:"ascalc.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7011.999"))
    {
      security_message(0);
      exit(0);
    }
  }
}

## SharePoint Server 2013
if(shareVer =~ "^15\..*")
{
  path = path + "\15.0\Bin";

  dllVer = fetch_file_version(sysPath:path, file_name:"ascalc.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4545.999"))
    {
      security_message(0);
      exit(0);
    }
  }
}

exit(99);