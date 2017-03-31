##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bsplayer_detect.nasl 5372 2017-02-20 16:26:11Z cfi $
#
# BS Player Free Edition Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "This script finds the installed version of BS Player Free Edition
  and saves the version in KB.";

if(description)
{
  script_id(800268);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5372 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:26:11 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BS Player Free Edition Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800268";
SCRIPT_DESC = "BS Player Free Edition Version Detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

# Method 1
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(registry_key_exists(key:key)){
   
  foreach item (registry_enum_keys(key:key))
  {
    bsName = registry_get_sz(key:key + item, item:"DisplayName");
    if("BS.Player" >< bsName)
    {
      bsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(bsVer != NULL)
      {
        set_kb_item(name:"BSPlayer/Ver", value:bsVer);
        log_message(data:" BS Player version " + bsVer + " was detected" + 
                           " on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:bsVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:bsplayer:bs.player:");

        exit(0);
      }
    }
  }
}

# Method 2
key2 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key2)){
    exit(0);
}

foreach item (registry_enum_keys(key:key2))
{
  bsName = registry_get_sz(key:key2 + item, item:"DisplayName");
  if("BS.Player" >< bsName || "BSPlayer" >< bsName)
  {
    path = registry_get_sz(key:key2 + item, item:"UninstallString");
    if(path != NULL)
    {
      exePath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:path);
      exePath = exePath - "uninstall.exe" + "bsplayer.exe";

      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);
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

    r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
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

    fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
    if(!fid)
    {
      close(soc);
      exit(0);
    }

    v = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, verstr:"prod",
                   offset:600000);
    close(soc);
    if(v != NULL)
    {
      set_kb_item(name:"BSPlayer/Ver", value:v);
      log_message(data:" BS Player version " + v + " was detected" +
                           " on the host"); 

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:v, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:bsplayer:bs.player:");

    }
    exit(0);
  }
}
