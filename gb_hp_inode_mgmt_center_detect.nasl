###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_inode_mgmt_center_detect.nasl 5372 2017-02-20 16:26:11Z cfi $
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

tag_summary = "Detection of installed version of HP iNode Management Center.

  The script logs in via smb, searches for HP iNode Management Center in the
  registry and gets the version from registry key.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802672";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5372 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:26:11 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2012-09-20 13:36:31 +0530 (Thu, 20 Sep 2012)");
  script_name("HP iNode Management Center Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

## Variable Initialization
keylist = "";
osArch = "";
key =  "";
keyfound = "";
item = "";
confmgrVer = "";
imcVer = "";
imcPath = "";
cpe = "";

## Confirm target is Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Check Processor Architecture
osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

## Check for 32 bit platform
if("x86" >< osArch){
 keylist = make_list("SOFTWARE\HP\iNode Management Center\");
}

## Check for 64 bit platform
else if("x64" >< osArch)
{
  keylist =  make_list("SOFTWARE\HP\iNode Management Center\",
                       "SOFTWARE\Wow6432Node\HP\iNode Management Center\");
}

if(isnull(keylist)){
  exit(0);
}

## Iterate over all registry paths
foreach key (keylist)
{
  ## Check the key existence
  if(registry_key_exists(key:key))
  {
    ## Iterate over all sub keys
    foreach item (registry_enum_keys(key:key))
    {
      ## Get the HP iMC product Version
      ## Set KB item for HP iNode Management Center
      if(eregmatch(pattern:'^([0-9.]+)$', string:item))
      {
          imcVer = item;
          ## Set Version in KB
          set_kb_item(name:"HP/iMC/Version", value:imcVer);

          ## Get the installed path
          newKey = "SOFTWARE\iNode\inodecenter\";
          newKeywow = "SOFTWARE\Wow6432Node\iNode\inodecenter\";

          ## Check the registry key existence
          if(registry_key_exists(key:newKey)){
              keyfound = newKey;
          }
          else if(registry_key_exists(key:newKeywow)){
              keyfound = newKeywow;
          }

          if (keyfound){
            ## Get Install Location
            imcPath = registry_get_sz(key: keyfound, item:"InstallDir");

            ## Check the installation path
            if(!imcPath || !eregmatch(pattern:"iNode Manager", string:imcPath)){
              imcPath = "Could not find the install Location from registry";
            }

            ## Set Path in KB
            set_kb_item(name:"HP/iMC/Path", value:imcPath);
          }

          ## Build CPE
          cpe = build_cpe(value:imcVer, exp:"^([0-9.]+)$", base:"cpe:/a:hp:inode_management_center_pc:");
          if(isnull(cpe))
            cpe = 'cpe:/a:hp:inode_management_center_pc';

          register_product(cpe:cpe, location:imcPath, nvt:SCRIPT_OID);

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
