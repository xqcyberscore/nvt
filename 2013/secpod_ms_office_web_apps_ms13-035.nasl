###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_office_web_apps_ms13-035.nasl 5339 2017-02-18 16:28:22Z cfi $
#
# Microsoft Office Web Apps HTML Sanitisation Component XSS Vulnerability (2821818)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could allow an attacker to bypass certain security
  restrictions and conduct cross-site scripting and spoofing attacks.
  Impact Level: Application";

tag_affected = "Microsoft Office Web Apps 2010 Service Pack 1";
tag_insight = "Certain unspecified input is not properly sanitized within the HTML
  Sanitation component before being returned to the user. This can be
  exploited to execute arbitrary HTML and script code in a user's
  browser session in context of an affected site.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-035";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-035.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902964";
CPE = "cpe:/a:microsoft:office_web_apps";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5339 $");
  script_bugtraq_id(58883);
  script_cve_id("CVE-2013-1289");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-18 17:28:22 +0100 (Sat, 18 Feb 2017) $");
  script_tag(name:"creation_date", value:"2013-04-10 11:55:11 +0530 (Wed, 10 Apr 2013)");
  script_name("Microsoft Office Web Apps HTML Sanitisation Component XSS Vulnerability (2821818)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52928/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2760777");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-035");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_web_apps_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Variables Initialization
version = "";
path = "";
dllVer = "";

## Microsoft Office Web Apps 2010 sp1
version = get_app_version(cpe:CPE, nvt:SCRIPT_OID);
if(!version){
  exit(0);
}

## Microsoft Office Web Apps 2010 sp1
if(version =~ "^14\..*")
{
  path = get_kb_item("MS/Office/Web/Apps/Path");
  if(path && "Could not find the install" >!< path )
  {
    path = path + "\14.0\WebServices\ConversionService\Bin\Converter";
    dllVer = fetch_file_version(sysPath:path, file_name:"msoserver.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6134.4999"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
