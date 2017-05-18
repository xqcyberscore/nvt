###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_detect_win.nasl 6032 2017-04-26 09:02:50Z teissa $
#
# Google Chrome Version Detection (Windows)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Update By:  Shakeel <bshakeel@secpod.com> on 2013-10-04
# According to cr57 and new style script_tags.
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800120";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6032 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-26 11:02:50 +0200 (Wed, 26 Apr 2017) $");
  script_tag(name:"creation_date", value:"2008-10-31 15:07:51 +0100 (Fri, 31 Oct 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Google Chrome Version Detection (Windows)");

  tag_summary =
"Detection of installed version of Google Chrome on Windows.

The script logs in via smb, searches for Google Chrome in the registry and gets
the version from registry.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
key="";
appName="";
enumKeys="";
chromeVer="";
chromePath="";
osArch = "";

# Get the Google Chrome Version from HKU (HKEY_USER).
function hku_registry_get_sz(key, item)
{
  if(!port){
    port = 139;
  }

  if(!get_port_state(port)){
    exit(0);
  }

  soc = open_sock_tcp(port);
  if(!soc){
    exit(0);
  }

  r = smb_session_request(soc:soc, remote:name);
  if(!r)
  {
    close(soc);
    exit(0);
  }

  prot = smb_neg_prot(soc:soc);
  if(!prot)
  {
    close(soc);
    exit(0);
  }

  r = smb_session_setup(soc:soc, login:login, password:pass,
                        domain:domain, prot:prot);
  if(!r)
  {
    close(soc);
    exit(0);
  }

  uid = session_extract_uid(reply:r);
  if(!uid)
  {
    close(soc);
    exit(0);
  }

  r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
  if(!r)
  {
    close(soc);
    exit(0);
  }

  tid = tconx_extract_tid(reply:r);
  if(!tid)
  {
    close(soc);
    exit(0);
  }

  r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
  if(!r)
  {
    close(soc);
    exit(0);
  }

  pipe = smbntcreatex_extract_pipe(reply:r);
  if(!pipe)
  {
    close(soc);
    exit(0);
  }

  r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
  if(!r)
  {
    close(soc);
    exit(0);
  }

  r = registry_open_hku(soc:soc, uid:uid, tid:tid, pipe:pipe);
  if(!r)
  {
    close(soc);
    exit(0);
  }

  key = key + "\Software\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome";

  r2 = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:r);
  if(r2)
  {
    r3 = registry_get_item_sz(soc:soc, uid:uid, tid:tid, pipe:pipe, item:item, reply:r2);
    registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2);
    registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r);
    if(r3){
      value = registry_decode_sz(data:r3);
    }
    close(soc);
    return value;
  }
  close(soc);
  return(FALSE);
}

## Get the OS architecture
osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

## if os is 32 bit iterate over comman path
if("x86" >< osArch){
 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Check for 64 bit platform
else if("x64" >< osArch){
 key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Confirm for Google Chrome
  if("Google Chrome" >< appName)
  {
    chromeVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(chromeVer)
    {
      chromePath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!chromePath){
        chromePath = "Couldn find the install location from registry";
      }

      set_kb_item(name:"GoogleChrome/Win/Ver", value:chromeVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:chromeVer, exp:"^([0-9.]+)", base:"cpe:/a:google:chrome:");
      if(isnull(cpe))
        cpe = "cpe:/a:google:chrome";

      register_product(cpe: cpe, location: chromePath, nvt: SCRIPT_OID);
      log_message(data: build_detection_report(app: "Google Chrome",
                                               version: chromeVer,
                                               install: chromePath,
                                                   cpe: cpe,
                                             concluded: chromeVer));
    }
  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\";
if(!registry_key_exists(key:key)){
  exit(0);
}

enumKeys = registry_enum_keys(key:key);

foreach key (enumKeys)
{
  chromeVer = hku_registry_get_sz(key:key, item:"Version");
  if(chromeVer)
  {
    chromePath = hku_registry_get_sz(key:key, item:"InstallLocation");
    if(!chromePath){
      chromePath = "Couldn find the install location from registry";
    }

    set_kb_item(name:"GoogleChrome/Win/Ver", value:chromeVer);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:chromeVer, exp:"^([0-9.]+)", base:"cpe:/a:google:chrome:");
    if(isnull(cpe))
     cpe = "cpe:/a:google:chrome";

    register_product(cpe: cpe, location: chromePath, nvt: SCRIPT_OID);
    log_message(data: build_detection_report(app: "Google Chrome",
                                             version: chromeVer,
                                             install: chromePath,
                                             cpe: cpe,
                                             concluded: chromeVer));


  }
}
