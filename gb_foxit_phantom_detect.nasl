###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_phantom_detect.nasl 8144 2017-12-15 13:19:55Z cfischer $
#
# Foxit Phantom Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "This script finds the Foxit Phantom version and saves
  the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801754");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 8144 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:19:55 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Foxit Phantom Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801754";
SCRIPT_DESC = "Foxit Phantom Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
       "\Foxit Phantom";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for Foxit Phantom DisplayName
name = registry_get_sz(key:key, item:"DisplayName");
if("Foxit Phantom" >< name)
{
  ## Get the version from registry
  foxitVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(foxitVer == NULL){
    exit(0);
  }
}

set_kb_item(name:"Foxit/Phantom/Ver", value:foxitVer);
set_kb_item(name:"Foxit/Phantom_or_Reader/Installed", value:TRUE);
log_message(data:"Foxit Phantom version " + foxitVer + " was detected on the host");
      
## build cpe and store it as host_detail
cpe = build_cpe(value:foxitVer, exp:"^([0-9.]+)", base:"cpe:/a:foxitsoftware:reader:");
if(!isnull(cpe))
   register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

