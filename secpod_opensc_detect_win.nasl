###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opensc_detect_win.nasl 9347 2018-04-06 06:58:53Z cfischer $
#
# OpenSC Version Detection (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_summary = "This script detects the version of OpenSC and sets the
  result in the KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901174");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9347 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 08:58:53 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenSC Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2011 SecPod");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901174";
SCRIPT_DESC = "OpenSC Version Detection (Windows)";

## Check for Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\OpenSC Project\OpenSC")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Get OpenSC version from registry
foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("OpenSC" >< name)
  {
    ver = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ver != NULL)
    {
      set_kb_item(name:"OpenSC/Win/Ver", value:ver);
      log_message(data:name + " version " + ver +
                         " was detected on the host");
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:opensc-project:opensc:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
