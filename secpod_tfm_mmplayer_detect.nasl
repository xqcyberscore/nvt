###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tfm_mmplayer_detect.nasl 8168 2017-12-19 07:30:15Z teissa $
#
# TFM MMPlayer Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_summary = "This script detects the version of TFM MMPlayer and
  sets the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900596");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8168 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("TFM MMPlayer Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900596";
SCRIPT_DESC = "TFM MMPlayer Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

tfmKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MMPlayer_is1";
tfmName = registry_get_sz(key:tfmKey, item:"DisplayName");

if("MMPlayer" >< tfmName)
{
  tfmPath = registry_get_sz(key:tfmKey, item:"UninstallString");
  tfmPath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:tfmPath);

  if(tfmPath != NULL)
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:tfmPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                        string:tfmPath - "\unins000.exe" + "\MMPlayer.exe");
    # Get the version of .exe file
    mmplayerVer = GetVer(file:file, share:share);

    if(mmplayerVer != NULL){
      set_kb_item(name:"TFM/MMPlayer/Ver", value:mmplayerVer);
      log_message(data:"TFM MMPlayer version " + mmplayerVer +
                         " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:mmplayerVer, exp:"^([0-9]\.[0-9])", base:"cpe:/a:tfm:mmplayer:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
