###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_metasploit_framework_detect_win.nasl 5499 2017-03-06 13:06:09Z teissa $
#
# Metasploit Framework Version Detection (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-05-28
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902293");
  script_version("$Revision: 5499 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-06 14:06:09 +0100 (Mon, 06 Mar 2017) $");
  script_tag(name:"creation_date", value:"2011-02-28 13:43:25 +0100 (Mon, 28 Feb 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Metasploit Framework Version Detection (Windows)");

  tag_summary =
"This script finds the installed Metasploit Framework version and saves the
version in KB.

The script logs in via smb, searches for Metasploit in the registry and gets
the version from  'DisplayVersion' string from the registry.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

## variable Initialization
os_arch = "";
key_list = "";
key = "";
msPath = "";
msVer = "";
msName = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

# Check for 64 bit platform, Currently only 64-bit application is available
else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
    exit(0);
}


## Get Metasploit Framework version from registry
foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    msName = registry_get_sz(key:key + item, item:"DisplayName");

    ## Confirm the application
    if("Metasploit" >< msName)
    {
      msVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(msVer)
      {
        msPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!msPath){
          msPath = "Couldn find the install location from registry";
        }

        ## Set the version in KB
        set_kb_item(name:"Metasploit/Framework/Win/Ver", value:msVer);

        ## build cpe and store it as host_detail
        cpe = build_cpe(value:msVer, exp:"^([0-9.]+)", base:"cpe:/a:metasploit:metasploit_framework:");
        if(isnull(cpe))
          cpe = "cpe:/a:metasploit:metasploit_framework";

        ## Register for 64 bit app on 64 bit OS once again
        if("64" >< os_arch && "Wow6432Node" >!< key)
        {
          ## Set the version in KB
          set_kb_item(name:"Metasploit/Framework64/Win/Ver", value:msVer);

          ## build cpe and store it as host_detail
          cpe = build_cpe(value:msVer, exp:"^([0-9.]+)", base:"cpe:/a:metasploit:metasploit_framework:64:");
          if(isnull(cpe))
            cpe = "cpe:/a:metasploit:metasploit_framework:64";

        }
        ## Register Product and Build Report
        register_product(cpe:cpe, location:msPath);

        log_message(data: build_detection_report(app: "Metasploit Framework",
                                                 version: msVer,
                                                 install: msPath,
                                                 cpe: cpe,
                                                 concluded: msVer));

      }
    }
  }
}
