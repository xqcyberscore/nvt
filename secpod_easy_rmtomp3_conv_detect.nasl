###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_easy_rmtomp3_conv_detect.nasl 9347 2018-04-06 06:58:53Z cfischer $
#
# Easy RmtoMp3 Converter Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod http://www.secpod.com
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
##############################################################################

tag_summary = "The script detects the installed Easy RmtoMp3 Converter application
  and sets the version in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900632");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9347 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 08:58:53 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Easy RmtoMp3 Converter Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900632";
SCRIPT_DESC = "Easy RmtoMp3 Converter Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
      exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  rmtomp3Name = registry_get_sz(item:"DisplayName", key:key + item);
  if(rmtomp3Name =~ "Easy RM to MP3 Converter")
  {
    rmtomp3Ver = eregmatch(pattern:" ([0-9.]+)",string:rmtomp3Name);
    if(rmtomp3Ver[1] != NULL){
      set_kb_item(name:"EasyRmtoMp3/Conv/Ver", value:rmtomp3Ver[1]);
      log_message(data:"Easy RmtoMp3 Converter version " + rmtomp3Ver[1] +
                                                " was detected on the host");
    
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:rmtomp3Ver[1], exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:mini-stream:easy_rm-mp3_converter:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
