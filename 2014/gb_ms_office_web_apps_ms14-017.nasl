###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_web_apps_ms14-017.nasl 9319 2018-04-05 08:03:12Z cfischer $
#
# Microsoft Office Web Apps Memory Corruption Vulnerability (2949660)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:microsoft:office_web_apps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804426");
  script_version("$Revision: 9319 $");
  script_cve_id("CVE-2014-1761");
  script_bugtraq_id(66385);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 10:03:12 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-04-09 12:19:57 +0530 (Wed, 09 Apr 2014)");
  script_name("Microsoft Office Web Apps Memory Corruption Vulnerability (2949660)");

  tag_summary = "This host is missing a critical security update according to
Microsoft Bulletin MS14-017.";

  tag_vuldetect = "Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight = "Flaw is due to the way that Microsoft Word parses specially crafted files.";

  tag_impact = "Successful exploitation will allow remote attackers to execute the arbitrary
code and take complete control of the affected system.

Impact Level: System/Application ";

  tag_affected = "Microsoft Office Web Apps 2010 Service Pack 2 and prior

Microsoft Office Web Apps 2013 Service Pack 1 and prior";

  tag_solution = "Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-017";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57577");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2878221");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2878219");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms14-017");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_web_apps_detect.nasl");
  script_mandatory_keys("MS/Office/Web/Apps/Ver");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
webappVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

if(webappVer =~ "^14\..*")
{
  ## Microsoft Office Web Apps 2010
  dllVer = fetch_file_version(sysPath:path,
           file_name:"\14.0\WebServices\ConversionService\Bin\Converter\msoserver.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7119.4999"))
    {
      security_message(0);
      exit(0);
    }
  }
}

## Microsoft Office Web Apps 2013
if(webappVer =~ "^15\..*")
{
  path = path + "\PPTConversionService\bin\Converter\";

  dllVer = fetch_file_version(sysPath:path, file_name:"msoserver.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4605.999"))
    {
      security_message(0);
      exit(0);
    }
  }
}

exit(99);