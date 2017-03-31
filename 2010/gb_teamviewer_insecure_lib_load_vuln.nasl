###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teamviewer_insecure_lib_load_vuln.nasl 5373 2017-02-20 16:27:48Z teissa $
#
# TeamViewer File Opening Insecure Library Loading Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
code and conduct DLL hijacking attacks via a Trojan horse dwmapi.dll that is
located in the same folder as a .tvs or .tvc file.

Impact Level: Application.";

tag_affected = "TeamViewer version 5.0.8703 and prior";

tag_insight = "The flaw is due to the application insecurely loading certain
librairies from the current working directory.";

tag_solution = "Update to version 5.0.9104 or later,
For updates refer to http://www.teamviewer.com/index.aspx";

tag_summary = "This host is installed with TeamViewer and is prone to insecure
library loading vulnerability.";

if(description)
{
  script_id(801436);
  script_version("$Revision: 5373 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:27:48 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)");
  script_cve_id("CVE-2010-3128");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("TeamViewer File Opening Insecure Library Loading Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41112");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14734/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2174");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\TeamViewer")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  teamName = registry_get_sz(key: key + item, item:"DisplayName");

  ## Check the name of the application
  if("TeamViewer" >< teamName)
  {
    ## Check for the version
    teamVer = registry_get_sz(key: key + item, item:"DisplayVersion");
    if(teamVer != NULL)
    {
      ## Check for TeamViewer version <= 5.0.8703
       if(version_is_less_equal(version:teamVer, test_version:"5.0.8703"))
       {
         security_message(0) ;
         exit(0);
      }
    }
  }
}
