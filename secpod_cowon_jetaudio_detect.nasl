###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cowon_jetaudio_detect.nasl 9347 2018-04-06 06:58:53Z cfischer $
#
# COWON Media Center JetAudio Version Detection
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

tag_summary = "This script detects the installed version of COWON Media
  Center JetAudio and sets the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900976");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9347 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 08:58:53 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("COWON Media Center JetAudio Version Detection");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900976";
SCRIPT_DESC = "COWON Media Center JetAudio Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\COWON\Jet-Audio")){
  exit(0);
}

jaPath = registry_get_sz(key:"SOFTWARE\COWON\Jet-Audio",
                         item:"InstallPath_Main");
if(jaPath == NULL)
{
  jaPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"+
                                   "\App Paths\JetAudio.exe", item:"Path");
  if(jaPath == NULL){
    exit(0);
  }
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:jaPath);
file = ereg_replace(pattern:"[A-Z]:(.*)",  replace:"\1",  string:jaPath +
                                                        "\JetAudio.exe");

jaVer = GetVer(file:file, share:share);
if(jaVer != NULL){
  set_kb_item(name:"JetAudio/Ver", value:jaVer);
  log_message(data:"COWON Media Center JetAudio version " + jaVer +
             " running at location " + jaPath + " was detected on the host");
  
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:jaVer, exp:"^([0-9.]+)", base:"cpe:/a:cowonamerica:cowon_media_center-jetaudio:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}
