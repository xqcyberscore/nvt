##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ruby_detect_win.nasl 8196 2017-12-20 12:13:37Z cfischer $
#
# Ruby Interpreter Version Detection (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2012-07-13
# Updated to check for recent version
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2013-11-27
# Updated according to cr57 and new style script_tags.
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-07-15
# Updated to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2009 SecPod, http//www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900799");
  script_version("$Revision: 8196 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 13:13:37 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Ruby Interpreter Version Detection (Windows)");

  script_tag(name: "summary" , value: "Detection of installed version of Ruby
  Interpreter on Windows.

  The script logs in via smb, searches for Ruby Interpreter in the registry
  and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable initialization
key = "";
key1 = "";
rubyVer = "";
rubyLoc = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch)
{
  key1_list = make_list("SOFTWARE\RubyInstaller\MRI\");
  key_list  = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Check for 32 bit App on 64 bit platform
else if("x64" >< os_arch)
{
  key1_list = make_list("SOFTWARE\RubyInstaller\MRI\",
                        "SOFTWARE\Wow6432Node\RubyInstaller\MRI\");
  key_list  = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Both 32 and 64 bit app registry is creating under wow6432node only.
## Tried installing Both 32 and 64 bit. Registry is not Creating Under uninstall Path.
## So Not able to test Under uninstall Path.

foreach key1 (key1_list)
{
  if(registry_key_exists(key:key1))
  {
    foreach item (registry_enum_keys(key:key1))
    {
      rubyLoc = registry_get_sz(key:key1 + item, item:"InstallLocation");
      if("Ruby" >< rubyLoc)
      {
        patch = registry_get_sz(key:key1 + item, item:"PatchLevel");
        build = registry_get_sz(key:key1 + item, item:"BuildPlatform");

        if(patch)
        {
          rubyVer = item  + ".p" + patch;
          set_kb_item(name:"Ruby/Win/Installed", value:TRUE);

          ## Register for 64 bit app on 64 bit OS
          if("64" >< os_arch && "x64" >< build) {
            set_kb_item(name:"Ruby64/Win/Ver", value:rubyVer);
            register_and_report_cpe( app:"Ruby", ver:rubyVer, concluded:rubyVer, base:"cpe:/a:ruby-lang:ruby:x64:", expr:"^([0-9.]+[a-z0-9]+?)", insloc:rubyLoc );
          } else {
            set_kb_item(name:"Ruby/Win/Ver", value:rubyVer);
            register_and_report_cpe( app:"Ruby", ver:rubyVer, concluded:rubyVer, base:"cpe:/a:ruby-lang:ruby:", expr:"^([0-9.]+[a-z0-9]+?)", insloc:rubyLoc );
          }
          exit(0);
        }
      }
    }
  }
}

## Check the Uninstall Path for the Application Installation
foreach key (key_list)
{
  if(registry_key_exists(key:key))
  {
    foreach item (registry_enum_keys(key:key))
    {
      rubyName = registry_get_sz(key:key + item, item:"DisplayName");
      if("Ruby" >< rubyName)
      {
        rubyVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        rubyLoc = registry_get_sz(key:key + item, item:"InstallLocation");
        if(rubyVer != NULL)
        {
          rubyVer = ereg_replace(pattern:"-", string:rubyVer, replace:".");
          set_kb_item(name:"Ruby/Win/Installed", value:TRUE);

          ## Register for 64 bit app on 64 bit OS
          if("64" >< os_arch && "Wow6432Node" >!< key) {
            set_kb_item(name:"Ruby64/Win/Ver", value:rubyVer);
            register_and_report_cpe( app:"Ruby", ver:rubyVer, concluded:rubyVer, base:"cpe:/a:ruby-lang:ruby:x64:", expr:"^([0-9.]+[a-z0-9]+?)", insloc:rubyLoc );
          } else {
            set_kb_item(name:"Ruby/Win/Ver", value:rubyVer);
            register_and_report_cpe( app:"Ruby", ver:rubyVer, concluded:rubyVer, base:"cpe:/a:ruby-lang:ruby:", expr:"^([0-9.]+[a-z0-9]+?)", insloc:rubyLoc );
          }
          exit(0);
        }
      }
    }
  }
}
