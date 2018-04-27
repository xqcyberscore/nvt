###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_inode_mgmt_center_detect.nasl 9633 2018-04-26 14:07:08Z jschulte $
#
# HP iNode Management Center Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802672");
  script_version("$Revision: 9633 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 16:07:08 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-09-20 13:36:31 +0530 (Thu, 20 Sep 2012)");
  script_name("HP iNode Management Center Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : "Detection of installed version of HP iNode Management Center.

  The script logs in via smb, searches for HP iNode Management Center in the
  registry and gets the version from registry key.");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
 keylist = make_list("SOFTWARE\HP\iNode Management Center\");
}

else if("x64" >< osArch)
{
  keylist =  make_list("SOFTWARE\HP\iNode Management Center\",
                       "SOFTWARE\Wow6432Node\HP\iNode Management Center\");
}

if(isnull(keylist)){
  exit(0);
}

foreach key (keylist)
{
  if(registry_key_exists(key:key))
  {
    foreach item (registry_enum_keys(key:key))
    {
      if(eregmatch(pattern:'^([0-9.]+)$', string:item))
      {
          imcVer = item;
          set_kb_item(name:"HP/iMC/Version", value:imcVer);

          newKey = "SOFTWARE\iNode\inodecenter\";
          newKeywow = "SOFTWARE\Wow6432Node\iNode\inodecenter\";

          if(registry_key_exists(key:newKey)){
              keyfound = newKey;
          }
          else if(registry_key_exists(key:newKeywow)){
              keyfound = newKeywow;
          }

          if (keyfound){
            imcPath = registry_get_sz(key: keyfound, item:"InstallDir");

            if(!imcPath || !eregmatch(pattern:"iNode Manager", string:imcPath)){
              imcPath = "Could not find the install Location from registry";
            }

            set_kb_item(name:"HP/iMC/Path", value:imcPath);
          }

          cpe = build_cpe(value:imcVer, exp:"^([0-9.]+)$", base:"cpe:/a:hp:inode_management_center_pc:");
          if(isnull(cpe))
            cpe = 'cpe:/a:hp:inode_management_center_pc';

          register_product(cpe:cpe, location:imcPath);

          log_message(data: build_detection_report(app:"HP iNode Management Center",
                                                   version: imcVer,
                                                   install: imcPath,
                                                   cpe:cpe,
                                                   concluded:imcVer));
      }
    }
    exit(0);
  }
}
