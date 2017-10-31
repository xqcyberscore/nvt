###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_flex_sdk_xss_vuln_win.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# Adobe Flex SDK Cross-Site Scripting Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_solution = "Upgrade to Flex SDK version 3.4
  http://opensource.adobe.com/wiki/display/flexsdk/Download+Flex+3

  ****************************************************************
  Note: This script detects Adobe Flex SDK installed as part of Adobe
  Flex Builder only. If SDK is installed separately, manual verification
  is required.
  ****************************************************************";

tag_impact = "Successful exploitation could allow remote attackers to cause XSS attacks by
  injecting arbitrary web script or HTML via the query string on the affected
  application.
  Impact Level: Application";
tag_affected = "Adobe Flex SDK version prior to 3.4 on Windows";
tag_insight = "The flaw is due to error in 'index.template.html' in the express-install
  templates and it occurs when the installed Flash version is older than a
  specified 'requiredMajorVersion' value.";
tag_summary = "This host is installed with Adobe Flex SDK and is prone to
  Cross-Site Scripting vulnerability.";

if(description)
{
  script_id(900829);
  script_version("$Revision: 7573 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1879");
  script_bugtraq_id(36087);
  script_name("Adobe Flex SDK Cross-Site Scripting Vulnerability (Windows)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/36374");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/52608");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-13.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/505948/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  flexName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Adobe Flex" >< flexName)
  {
    sdkPath = registry_get_sz(key:key + item, item:"FrameworkPath");

    if("sdk" >< sdkPath)
    {
      sdkVer = eregmatch(pattern:"\\([0-9.]+)", string:sdkPath);

      if(!isnull(sdkVer[1]))
      {
        # Check for Flex SDK version < 3.4
        if(version_is_less(version:sdkVer, test_version:"3.4")){
          security_message(0);
        }
      }
    }
    exit(0);
  }
}
