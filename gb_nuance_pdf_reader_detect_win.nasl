###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuance_pdf_reader_detect_win.nasl 5877 2017-04-06 09:01:48Z teissa $
#
# Nuance PDF Reader Version Detection (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-07-08
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803328");
  script_version("$Revision: 5877 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-06 11:01:48 +0200 (Thu, 06 Apr 2017) $");
  script_tag(name:"creation_date", value:"2013-03-11 15:20:19 +0530 (Mon, 11 Mar 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Nuance PDF Reader Version Detection (Windows)");

  tag_summary =
"Detection of installed version of Nuance PDF Reader on Windows.

The script logs in via smb, searches for Nuance PDF Reader in the
registry and gets the version from registry";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable Initialization
os_arch = "";
key_list = "";
ReaderName = "";
ReaderPath = "";
ReaderVer = "";
cpe = "";
key = "";

# Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Check for 64 bit platform, Currently only 32-bit application is available
else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    ## Check for the Application
    ReaderName = registry_get_sz(key:key + item, item:"DisplayName");
    if("Nuance PDF Reader" >< ReaderName)
    {
      ## Check for the install path
      ReaderPath =registry_get_sz(key:key + item, item:"InstallLocation");
      if(!ReaderPath){
        ReaderPath = "Could not find the install Location";
      }

      ## Check for the version
      ReaderVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(ReaderVer)
      {
        set_kb_item(name:"Nuance/PDFReader/Win/Ver", value:ReaderVer);

        ## Build cpe
        cpe = build_cpe(value:ReaderVer, exp:"^([0-9.]+)", base:"cpe:/a:nuance:pdf_reader:");
        if(isnull(cpe))
          cpe = "cpe:/a:nuance:pdf_reader";

        register_product(cpe:cpe, location:ReaderPath);
        log_message(data: build_detection_report(app:"Nuance PDF Reader",
                                               version:ReaderVer,
                                               install:ReaderPath,
                                               cpe:cpe,
                                               concluded:ReaderVer));
      }
    }
  }
}
