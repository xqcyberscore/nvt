###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_code_exec_vuln_jul09_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Products '.pdf' and '.swf' Code Execution Vulnerability - July09 (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900806");
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-2009-1862");
  script_bugtraq_id(35759);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_name("Adobe Products '.pdf' and '.swf' Code Execution Vulnerability - July09 (Windows)");

  tag_summary = "This host is installed with Adobe products and are prone to remote code
execution vulnerability.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight = "- An unspecified error exists in Adobe Flash Player which can be exploited via
a specially crafted flash application in a '.pdf' file.

- Error occurs in 'authplay.dll' in Adobe Reader/Acrobat whlie processing '.swf'
content and can be exploited to execute arbitrary code.";

  tag_impact = "Successful exploitation will allow remote attackers to cause code execution.

Impact Level: Application";

  tag_affected = "Adobe Reader/Acrobat version 9.x to 9.1.2

Adobe Flash Player version 9.x to 9.0.159.0 and 10.x to 10.0.22.87 on Windows.";

  tag_solution = "Upgrade to Adobe Reader/Acrobat version 9.1.3 or later.
Upgrade to Adobe Flash Player version 9.0.246.0 or 10.0.32.18 or later.
For updates refer to http://www.adobe.com/";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/35948/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35949/");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/259425");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa09-03.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl", "secpod_adobe_prdts_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:flash_player";
if(playerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  # Check for Adobe Flash Player version 9.x to 9.0.159.0 or 10.x to 10.0.22.87
  if(version_in_range(version:playerVer, test_version:"9.0", test_version2:"9.0.159.0") ||
     version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.0.22.87"))
  {
    security_message(0);
  }
}

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  authplayDll = registry_get_sz(key:"SOFTWARE\Adobe\Acrobat Reader\9.0" +
                                    "\Installer", item:"Path");
  if(!authplayDll){
    break;
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:authplayDll);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:authplayDll + "\Reader\authplay.dll");
  fileVer = GetVer(file:file, share:share);

  if(fileVer =~ "9.0")
  {
    # Check for Adobe Reader version 9.x to 9.1.2
    if(version_in_range(version:readerVer, test_version:"9.0",
                                           test_version2:"9.1.2")){
      security_message(0);
    }
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{
  authplayDll = registry_get_sz(key:"SOFTWARE\Adobe\Adobe Acrobat\9.0" +
                                    "\Installer", item:"Path");
  if(!authplayDll){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:authplayDll);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:authplayDll + "\Acrobat\authplay.dll");

  fileVer = GetVer(file:file, share:share);
  if(fileVer =~ "9.0")
  {
    # Check for Adobe Acrobat version 9.x to 9.1.2
    if(version_in_range(version:acrobatVer, test_version:"9.0",
                                            test_version2:"9.1.2"))
    {
      security_message(0);
      exit(0);
    }
  }
}
