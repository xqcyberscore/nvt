##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaspersky_av_detect.nasl 9600 2018-04-25 08:48:41Z asteins $
#
# Kaspersky AntiVirus Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated to detect Kaspersky Internet Security and Anti-Virus for
# Windows File Servers.
# By - Nikita MR <rnikita@secpod.com> on 2010-01-06
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-08-04
# According to CR57 and to support 32 and 64 bit.
#
# Updated By: Rinu Kuriakose <krinu@secpod.com> on 2017-01-06
# for detecting 2017 version of anti virus, total security and internet security
# and adding one more key for application confirmation
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800241");
  script_version("$Revision: 9600 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-25 10:48:41 +0200 (Wed, 25 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-16 16:42:20 +0100 (Mon, 16 Feb 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Kaspersky AntiVirus Version Detection");

  tag_summary =
"This script finds the installed Kaspersky Products-Kaspersky AntiVirus, 
kaspersky total security and Kaspersky Internet Security and saves the version.

The script logs in via smb, searches for Kaspersky AntiVirus and Kaspersky
Internet Security in the registry and gets the version from registry";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

INTNETSEC_LIST = make_list( "^(7\..*)", "cpe:/a:kaspersky_lab:kaspersky_internet_security:",
                         "^(8\..*)", "cpe:/a:kaspersky_lab:kaspersky_internet_security_2009:",
                         "^(9\..*)", "cpe:/a:kaspersky_lab:kaspersky_internet_security_2010:",
                         "^(15\..*)", "cpe:/a:kaspersky_lab:kaspersky_internet_security_2015:",
                         "^(16\..*)", "cpe:/a:kaspersky_lab:kaspersky_internet_security:",
                         "^(17\..*)", "cpe:/a:kaspersky_lab:kaspersky_internet_security_2017:");
INTNETSEC_MAX = max_index(INTNETSEC_LIST);

AV_LIST = make_list("^(9\..*)", "cpe:/a:kaspersky:kaspersky_anti-virus:2010",
                    "^(8\..*)", "cpe:/a:kaspersky:kaspersky_anti-virus:2009",
                    "^(7\..*)", "cpe:/a:kaspersky:kaspersky_anti-virus:2008",
                    "^(6\..*)", "cpe:/a:kaspersky:kaspersky_anti-virus:2007",
                    "^(11\..*)", "cpe:/a:kaspersky:kaspersky_anti-virus:2011",
                    "^(16\..*)", "cpe:/a:kaspersky:kaspersky_anti-virus:",
                    "^(17\..*)", "cpe:/a:kaspersky:kaspersky_anti-virus_2017:");
AV_MAX = max_index(AV_LIST);

TOTSEC_LIST = make_list("^(15\..*)", "cpe:/a:kaspersky:total_security_2015:",
                        "^(16\..*)", "cpe:/a:kaspersky:kaspersky_total_security:",
                        "^(17\..*)", "cpe:/a:kaspersky:kaspersky_total_security_2017:");
TOTSEC_MAX = max_index(TOTSEC_LIST);

# Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Check for 64 bit platform, Currently only 32-bit application is available
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(isnull(key)){
  exit(0);
}

##Confirm Application
if(registry_key_exists(key:"SOFTWARE\KasperskyLab")){
  set_kb_item(name:"Kaspersky/products/installed", value:TRUE);
} else{
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  prdtName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Kaspersky" >< prdtName)
  {
    # Check for Kaspersky Anti-Virus for Windows Workstations.
    if("Anti-Virus" >< prdtName && "Windows Workstations" >< prdtName)
    {
      kavwVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      insloc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insloc){
        insloc = "Could not determine install Path";
      }
      if(kavwVer)
      {
        set_kb_item(name:"Kaspersky/products/installed", value:TRUE);
        set_kb_item(name:"Kaspersky/AV-Workstation/Ver", value:kavwVer);
        ## build cpe and store it as host_detail
        register_and_report_cpe(app:"Kaspersky Anti-Virus", ver:kavwVer, base:"cpe:/a:kaspersky_lab:kaspersky_anti-virus:6.0::workstations",
                                expr:"^(6\.0)", insloc:insloc);
      }
    }
  }

  # Check for Kaspersky Anti-Virus for Windows File Servers.
  if("Anti-Virus" >< prdtName && "File Servers" >< prdtName)
  {
    kavsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    insloc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!insloc){
        insloc = "Could not determine install Path";
    }
    if(kavsVer != NULL)
    {
      set_kb_item(name:"Kaspersky/products/installed", value:TRUE);
      set_kb_item(name:"Kaspersky/AV-FileServer/Ver", value:kavsVer);

      ## build cpe and store it as host_detail
      register_and_report_cpe(app:"Kaspersky Anti-Virus", ver:kavsVer,
                              base:"cpe:/a:kaspersky_lab:kaspersky_anti-virus:6.0.3.837::windows_file_servers:",
                              expr:"^(6\.0)", insloc:insloc);
    }
  }

  # Check for Kaspersky Anti-Virus.
  if(prdtName =~ "Kaspersky Anti-Virus [0-9]+" || prdtName =~ "Kaspersky Anti-Virus")
  {
    kavVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    insloc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!insloc){
        insloc = "Could not determine install Path";
    }
    if(kavVer != NULL)
    {
      set_kb_item(name:"Kaspersky/products/installed", value:TRUE);
      set_kb_item(name:"Kaspersky/AV/Ver", value:kavVer);

      ## build cpe and store it as host_detail
      for (i = 0; i < AV_MAX-1; i = i + 2){
        register_and_report_cpe(app:"Kaspersky Anti-Virus", ver:kavVer,
                              base:AV_LIST[i+1],
                              expr:AV_LIST[i], insloc:insloc);
      }
    }
  }

  # Check for Kaspersky Internet Security.
  if("Internet Security" >< prdtName)
  {
    kisVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    insloc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!insloc){
      insloc = "Could not determine install Path";
    }

    if(kisVer != NULL)
    {
      set_kb_item(name:"Kaspersky/products/installed", value:TRUE);
      set_kb_item(name:"Kaspersky/IntNetSec/Ver", value:kisVer);

      ## build cpe and store it as host_detail
      for (i = 0; i < INTNETSEC_MAX-1; i = i + 2)
      {
        register_and_report_cpe(app:"Kaspersky Internet Security", ver:kisVer,
                              base:INTNETSEC_LIST[i+1],
                              expr:INTNETSEC_LIST[i], insloc:insloc);

      }
    }
  }
  if("Total Security" >< prdtName)
  {
    kisVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    insloc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!insloc){
      insloc = "Could not determine install Path";
    }

    if(kisVer != NULL)
    {
      set_kb_item(name:"Kaspersky/products/installed", value:TRUE);
      set_kb_item(name:"Kaspersky/TotNetSec/Ver", value:kisVer);

      ## build cpe and store it as host_detail
      for (i = 0; i < TOTSEC_MAX-1; i = i + 2)
      {
        register_and_report_cpe(app:"Kaspersky Total Security", ver:kisVer,
                              base:TOTSEC_LIST[i+1],
                              expr:TOTSEC_LIST[i], insloc:insloc);
      }
    }
  }

}
