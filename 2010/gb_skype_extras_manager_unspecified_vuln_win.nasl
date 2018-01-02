###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_skype_extras_manager_unspecified_vuln_win.nasl 8228 2017-12-22 07:29:52Z teissa $
#
# Skype Extras Manager Unspecified Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "It has unknown impact and attack vectors.
  Impact Level: System/Application";
tag_affected = "Skype version prior to 4.1.0.179 on windows.";
tag_insight = "The flaw is caused by unspecified errors in the 'Extras Manager component'.";
tag_solution = "Upgrade to Skype version 4.1.0.179 or later,
  For updates refer to http://www.skype.com/intl/en/download/skype/windows/";
tag_summary = "The host is installed with Skype and is prone to unspecified
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801302");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2009-4741");
  script_bugtraq_id(36459);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Skype Extras Manager Unspecified Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37012");
  script_xref(name : "URL" , value : "https://developer.skype.com/WindowsSkype/ReleaseNotes#head-21c1b2583e7cc405f994ca162d574fb15a6e986b");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_skype_detect_win.nasl");
  script_require_keys("Skype/Win/Ver");
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
include("version_func.inc");
include("secpod_smb_func.inc");

skypeVer = get_kb_item("Skype/Win/Ver");
if(!skypeVer){
  exit(0);
}

if(!version_is_less(version:skypeVer, test_version:"4.1.0.179")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("Skype" >< name)
  {
    skypePath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!isnull(skypePath))
    {
      skypePath = skypePath + "Plugin Manager\skypePM.exe";
      share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:skypePath);
      file  =  ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:skypePath);

      ver = GetVer(file:file, share:share);
      if(ver != NULL)
      {
        if(version_is_less(version:ver, test_version:"2.0.0.67"))
        {
          security_message(0);
          exit(0);
        }
      }
    }
  }
}
