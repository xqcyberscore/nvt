###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sharepoint_designer_detect.nasl 9584 2018-04-24 10:34:07Z jschulte $
#
# Microsoft SharePoint Designer Detection
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804585";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 9584 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-24 12:34:07 +0200 (Tue, 24 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-05-14 16:18:27 +0530 (Wed, 14 May 2014)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft SharePoint Designer Detection");

  tag_summary =
"Detection of installed version of Microsoft SharePoint Designer.

The script logs in via smb, searches through the registry and gets the
version and sets the KB.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable Initialization
cpe = "";
spVer = "";
spName = "";
insPath = "";

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  if(spName = registry_get_sz(key:key + item, item:"DisplayName"))
  {
    ## Check for SharePoint Server
    if("Microsoft SharePoint Designer" >< spName)
    {
      spVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(spVer)
      {
        ## Get the installation path
        insPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!insPath){
          insPath = "Could not find the install location from registry";
        }

        ## Set the KB item
        set_kb_item(name:"MS/SharePoint/Designer/Ver", value:spVer);
        cpe = build_cpe(value:spVer, exp:"^([0-9.]+[a-z0-9]*)",
                             base:"cpe:/a:microsoft:sharepoint_designer:");

        if(!cpe){
          cpe = "cpe:/a:microsoft:sharepoint_designer";
        }

        register_product(cpe:cpe, location:insPath);

        log_message(data: build_detection_report(app:spName, version:spVer,
                                                 install:insPath, cpe:cpe,
                                                 concluded: spVer));
      }
    }
  }
}
