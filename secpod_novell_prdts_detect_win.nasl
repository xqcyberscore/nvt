####################################G###########################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_prdts_detect_win.nasl 7076 2017-09-07 11:53:47Z teissa $
#
# Novell Multiple Products Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Modified by: Nikita MR (rnikita@secpod.com)
# Date: 24th July 2009
# Changes: Modified the kb name to indicate windows version.
#
# Modified by: Nikita MR (rnikita@secpod.com)
# Date: 09th Nov 2009
# Changes: Added check for Novell Groupwise client.
#
# Updated by: Madhuri D  <dmadhuri@secpod.com> on 2010-08-13
#  Modified to detect recent versions.
#
# Update By: Antu Sanadi <santu@secpod.com> on 2011-04-12
# Updated to detect Novell File Reporter.
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-09-17
# To support 32 and 64 bit.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900340");
  script_version("$Revision: 7076 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-07 13:53:47 +0200 (Thu, 07 Sep 2017) $");
  script_tag(name:"creation_date", value:"2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Novell Multiple Products Version Detection");

    tag_summary =
"This script detects the installed version of Novell Products and sets the
result in KB.";


  script_tag(name : "summary" , value : tag_summary);

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
include("version_func.inc");

## Variable Initialisation
os_arch = "";
key = "";
cpe = "";
install = "";
eDirName = "";
eDirVer = "";
eDirPath = "";
clientVer = "";
clientPath = "";
netidName = "";
netidPath = "";
nfrName = "";
nfrPath = "";
nfrVer = "";
gcPath = "";
gcVer = "";
iprintName = "";
iprintVer = "";

##Confirm Applications
if(!registry_key_exists(key:"SOFTWARE\Novell"))
{
  if(!registry_key_exists(key:"SOFTWARE\Novell-iPrint"))
  {
    if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Novell")){
      exit(0);
    }
  }
}

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

# Check for 32 bit platform
if("x86" >< os_arch){
  key_novell = make_list("SOFTWARE\Novell");
  key_iprint = "SOFTWARE\Novell-iPrint";
}

## Check for 64 bit platform
else if("x64" >< os_arch){
  key_novell = make_list("SOFTWARE\Novell", "SOFTWARE\Wow6432Node\Novell");
  key_iprint = "SOFTWARE\Novell-iPrint";
}

foreach key(key_novell)
{
  # Set KB for Novell eDirectory (NDSD), 32-bit app not installing on 64-bit Architecture
  if(registry_key_exists(key:key + "\NDS"))
  {
    eDirName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                 "\Uninstall\NDSonNT", item:"DisplayName");
    if("eDirectory" >< eDirName)
    {
      eDirVer = eregmatch(pattern:"([0-9]\.[0-9.]+).?(SP[0-9])?", string:eDirName);
      eDirPath = "Could not find install location" ;
      if(eDirVer[1] != NULL && eDirVer[2] != NULL){
        eDirVer = eDirVer[1] + "." + eDirVer[2];
      }
      else{
        eDirVer = eDirVer[1];
      }
      if(eDirVer)
      {
        set_kb_item(name:"Novell/eDir/Win/Ver", value:eDirVer);

        ## Build CPE
        cpe = build_cpe(value:eDirVer, exp:"^([0-9.]+([a-z0-9]+)?)",
                        base:"cpe:/a:novell:edirectory:");
        if(isnull(cpe))
          cpe = 'cpe:/a:novell:edirectory';

        ## 64 bit apps on 64 bit platform
        if("x64" >< os_arch)
        {
          set_kb_item(name:"Novell/eDir/Win64/Ver", value:eDirVer);

          ## build cpe and store it as host_detail
          cpe = build_cpe(value:eDirVer, exp:"^([0-9.]+([a-z0-9]+)?)",
                          base:"cpe:/a:novell:edirectory:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:novell:edirectory:x64";

        }
        build_report(app:"Novell eDirectory", ver:eDirVer, cpe:cpe,
                     insloc:eDirPath, concluded:eDirVer);
      }
    }
  }

  ##32-bit install not possible on 64-bit Architecture
  # Set KB for Novell Client
  if(registry_key_exists(key:key))
  {
    clientVer = registry_get_sz(key:key + "\NetWareWorkstation\CurrentVersion",
                                item:"ProductName");
    clientPath = "Could not find install location";
    if(!clientVer){
      clientVer = registry_get_sz(key:key + "\Client\Version", item:"ProductName");
    }

    if("Novell Client" >< clientVer)
    {
      clientVersion = eregmatch(pattern:"([0-9]\.[0-9.]+).?(SP[0-9]+)?", string:clientVer);
      if(clientVersion[1] != NULL && clientVersion[2] != NULL){
        clientVersion = clientVersion[1] + "." + clientVersion[2];
      }
      else if(clientVersion[1] =~ "[0-9]+"){
        clientVersion = clientVersion[1];
      }
      if(clientVersion[0] == NULL)
      {
        clientVersion = eregmatch(pattern:"([0-9]+).(SP[0-9]+)?", string:clientVer);
        if(clientVersion[1] != NULL && clientVersion[2] != NULL){
          clientVersion = clientVersion[1] + "." + clientVersion[2];
        }
      }
    }
    else{
      clientVersion = registry_get_sz(key:key, item:"CurrentVersion");
    }

    if(clientVersion)
    {
      set_kb_item(name:"Novell/Client/Ver", value:clientVersion);

      ## Build CPE
      cpe = build_cpe(value:clientVer, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:novell:client:");
      if(isnull(cpe))
        cpe = 'cpe:/a:novell:client';

      ## 64 bit apps on 64 bit platform
      if("x64" >< os_arch)
      {
        set_kb_item(name:"Novell/Client64/Ver", value:clientVersion);

        ## build cpe and store it as host_detail
        cpe = build_cpe(value:clientVer, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:novell:client:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:novell:client:x64:";

      }
      build_report(app:"Novell Client", ver:clientVersion, cpe:cpe, insloc:clientPath, concluded:clientVersion);
    }
  }

  # Set KB for Novell NetIdentity, only 32-bit application available
  if(registry_key_exists(key: key + "\NetIdentity"))
  {
    unins_key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
    if("x64" >< os_arch){
      unins_key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
    }
    foreach item (registry_enum_keys(key:unins_key))
    {
      netidName = registry_get_sz(key:unins_key + item, item:"DisplayName");

      if("NetIdentity" >< netidName)
      {
        netidVer = eregmatch(pattern:"([0-9]\.[0-9.]+)", string:netidName);
        netidPath = registry_get_sz(key:unins_key + item, item:"InstallLocation");
        if(!netidPath){
          netidPath = "Could not find install location";
        }
        if(netidVer[1] != NULL)
        {
          set_kb_item(name:"Novell/NetIdentity/Ver", value:netidVer[1]);

          ## build cpe and store it as host_detail
          cpe = build_cpe(value:netidVer[1], exp:"^([0-9.]+)",
                          base:"cpe:/a:novell:netidentity_client:");
          if(!cpe)
            cpe="cpe:/a:novell:netidentity_client";

          build_report(app:"Novell NetIdentity", ver:netidVer[1],
                       cpe:cpe, insloc:netidPath, concluded:netidVer[1]);

          buildVer = registry_get_sz(key:unins_key + item, item:"DisplayVersion");
          if(!buildVer){
            buildVer = registry_get_sz(key: key + "NetIdentity", item:"Version");
          }
          if(buildVer){
            set_kb_item(name:"Novell/NetIdentity/Build/Ver", value:buildVer);
          }
        }
      }
    }
  }

  # Set kb for Novell Groupwise Client, only 32-bit version is available
  if(registry_key_exists(key: key + "\GroupWise"))
  {
    gcPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"+
                                 "\App Paths\GrpWise.exe", item:"Path");
    if(gcPath != NULL)
    {
      gcVer = fetch_file_version(sysPath:gcPath, file_name:"GrpWise.exe");
      if(gcVer != NULL)
      {
        set_kb_item(name:"Novell/Groupwise/Client/Win/Ver", value:gcVer);

        ## Build CPE
        cpe = build_cpe(value:gcVer, exp:"^([0-9.]+)", base:"cpe:/a:novell:groupwise:");
        if(isnull(cpe))
          cpe = 'cpe:/a:novell:groupwise';

        build_report(app:"Novell Groupwise Client", ver:gcVer,
                     cpe:cpe, insloc:gcPath, concluded:gcVer);
      }
    }
  }

  # Set KB for Novell File Reporter, 32-bit application cannot be installed on 64-bit architecture
  if(registry_key_exists(key: key + "\File Reporter"))
  {
    unins_key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
    foreach item (registry_enum_keys(key:unins_key))
    {
      nfrName = registry_get_sz(key:unins_key + item, item:"DisplayName");
      if("Novell File Reporter" >< nfrName)
      {
        nfrPath = registry_get_sz(key:unins_key + item, item:"InstallLocation");
        if(!nfrPath){
          nfrPath = "Could not find install location";
        }
        nfrVer = registry_get_sz(key:unins_key + item, item:"DisplayVersion");
        if(nfrVer != NULL)
        {
          set_kb_item(name:"Novell/FileReporter/Ver", value:nfrVer);

          ## Build CPE
          cpe = build_cpe(value:nfrVer, exp:"^([0-9.]+)",
                          base:"cpe:/a:novell:file_reporter:");
          if(isnull(cpe))
            cpe = 'cpe:/a:novell:file_reporter';

          ## 64 bit apps on 64 bit platform
          if("x64" >< os_arch)
          {
            set_kb_item(name:"Novell/FileReporter64/Ver", value:nfrVer);

            ## build cpe and store it as host_detail
            cpe = build_cpe(value:nfrVer, exp:"^([0-9.]+)", base:"cpe:/a:novell:file_reporter:x64:");
            if(isnull(cpe))
              cpe = "cpe:/a:novell:file_reporter:x64:";
          }
          build_report(app:"Novell File Reporter", ver:nfrVer, cpe:cpe, insloc:nfrPath, concluded:nfrVer);
        }
      }
    }
  }
}


##Novell-iPrint Client 32-bit app cannot be installed on 64-bit Architecture
## Set KB for Novell iPrint Client
## Check application is installed
if(registry_key_exists(key:key_iprint))
{
  ver = registry_get_sz(key:key_iprint, item:"Current Version");
  ip_key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Novell iPrint Client";
  install=registry_get_sz(key:ip_key, item:"UninstallString");
  if(ver && install)
  {
    iprintVer = eregmatch(pattern:"([0-9.]+)" , string:ver);
    iprintVer = iprintVer[1];
    install= install-"/uninstall";
  }
  else
  {
    iprintName = registry_get_sz(key:ip_key, item:"DisplayName");
    install=registry_get_sz(key:ip_key, item:"UninstallString");
    if("iPrint" >< iprintName)
    {
      iprintVer = eregmatch(pattern:"v([0-9.]+)", string:iprintName);
      if(iprintVer[1]){
          iprintVer = iprintVer[1];
          install= install-"/uninstall";
      }
    }
  }

  if(iprintVer)
  {
    set_kb_item(name:"Novell/iPrint/Ver", value:iprintVer);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:iprintVer, exp:"^([0-9.]+)",
                        base:"cpe:/a:novell:iprint:");
    if(!cpe)
      cpe="cpe:/a:novell:iprint";

    ## 64 bit apps on 64 bit platform
    if("x64" >< os_arch)
    {
      set_kb_item(name:"Novell/iPrint64/Ver", value:iprintVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:iprintVer, exp:"^([0-9.]+)", base:"cpe:/a:novell:iprint:x64:");
      if(isnull(cpe))
        cpe = "cpe:/a:novell:iprint:x64:";

    }
    build_report(app:"Novell iPrint Client", ver:iprintVer, cpe:cpe, insloc:install, concluded:iprintVer);
  }
}
