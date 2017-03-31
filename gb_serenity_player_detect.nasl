###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_serenity_player_detect.nasl 5372 2017-02-20 16:26:11Z cfi $
#
# Serenity/Mplay Player Version Detection
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

tag_summary = "This script detects the installed version of Serenity/Mplay
  Audio Player and sets the reuslt in KB.";

if(description)
{
  script_id(800728);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5372 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:26:11 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Serenity/Mplay Player Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800728";
SCRIPT_DESC = "Serenity/Mplay Player Version Detection";

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

function find_version(path, file)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:file);
  serenityVer = GetVer(file:file, share:share);
  return serenityVer;
}

appKey  = "SOFTWARE\Serenity Audio Player";
appKey2 = "SOFTWARE\Malx media player";
if(!registry_key_exists(key:appKey) && !registry_key_exists(key:appKey2)){
  exit(0);
}

appPath  = registry_get_sz(key:appKey, item:"Install_Dir");
appPath2 = registry_get_sz(key:appKey2, item:"Install_Dir");

if(appPath != NULL)
{
  serenityVer = find_version(path:appPath, file:appPath +"\serenity.exe");
  if(serenityVer != NULL)
  {
    set_kb_item(name:"Serenity/Audio/Player/Ver", value:serenityVer);
    log_message(data:"Serenity Audio Player version " + serenityVer +
                       " running at location " + appPath +
                       " was detected on the host"); 

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:serenityVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:malsmith:serenity_audio_player:");
  }
}

if(appPath2 != NULL)
{
  mplayVer = find_version(path:appPath2, file:appPath2 + "\mplay.exe");
  if(mplayVer != NULL)
  {
    set_kb_item(name:"Mplay/Audio/Player/Ver", value:mplayVer);
    log_message(data:"Malx media player version " + mplayVer +
                       " running at location " + appPath2 +
                       " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:mplayVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:malsmith:serenity_audio_player:");
  }
}
