###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nidesoft_mp3_conv_detect_win.nasl 7000 2017-08-24 11:51:46Z teissa $
#
# Nidesoft MP3 converter Detection (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107107");
  script_version("$Revision: 7000 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-24 13:51:46 +0200 (Thu, 24 Aug 2017) $");
  script_tag(name:"creation_date", value:"2016-12-19 11:19:11 +0530 (Mon, 19 Dec 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("gb_cisco_webexwrf_detect_win.nasl (Windows)");

  script_tag(name: "summary" , value: "Detection of installed version of
  Nidesoft MP3 converter.

  The script logs in via smb, searches for Nidesoft MP3 converter in the registry and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}
include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## variable Initialization
os_arch = "";
key_list = "";
key = "";
cvPath = "";
cvVer = "";
cvName = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

#check for 64 bit platform
else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
   cvName = registry_get_sz(key:key + item, item:"DisplayName");

   if(cvName =~ "Nidesoft MP3 Converter" )
    {
      cvVer = eregmatch(pattern: "Nidesoft MP3 Converter v([0-9.]+)", string: cvName);
      if (!isnull( cvVer[1])) cvVer = cvVer[1];
      cvPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!cvPath){
        cvPath = "Unable to find the install location from registry";
      }

      if(cvVer)
      {
        set_kb_item(name:"Nidesoft/Mp3converter/Win/Ver", value:cvVer);
        cpe = build_cpe(value:cvVer, exp:"^([0-9.]+)", base:"cpe:/a:Nidesoft:mp3_converter:");
        if(isnull(cpe))
          cpe = "cpe:/a:Nidesoft:mp3_converter";

        if("x64" >< os_arch && "x86" >!< cvPath)
        {
          set_kb_item(name:"Nidesoft/Mp3converter/Win/Ver", value:cvVer);
          cpe = build_cpe(value:cvVer, exp:"^([0-9.]+)", base:"Nidesoft/Mp3converter/Win/Ver:x64:");
          if(isnull(cpe))
            cpe = "Nidesoft/Mp3converter/Win/Ver:x64";
        }

       register_product(cpe:cpe, location:cvPath);
       log_message(data: build_detection_report(app: "Nidesoft MP3 converter",
                                                version: cvVer,
                                                install: cvPath,
                                                cpe: cpe,
                                                concluded: cvVer));
      }
    }
  }
}


