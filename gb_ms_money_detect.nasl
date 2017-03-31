###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_money_detect.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# Microsoft Money Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800217";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 5351 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-01-08 14:06:04 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Money Version Detection");

tag_summary =
"Detection of installed version of Microsoft Money on Windows.

The script logs in via smb, searches for Microsoft Money in the registry
and gets the version from registry.";


  script_tag(name : "summary" , value : tag_summary);

  script_summary("Detection of installed version of Microsoft Money in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

## Function to Register Product and Build report
function build_report(app, ver, cpe, insloc)
{
  register_product(cpe:cpe, location:insloc, nvt:SCRIPT_OID);

  log_message(data: build_detection_report(app: app,
                                           version: ver,
                                           install: insloc,
                                           cpe: cpe,
                                           concluded: ver));
}

osArch = "";
key_list = "";
key = "";
item = "";
InstallPath = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

## if os is 32 bit iterate over comman path
if("x86" >< osArch){
  key_list = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Check for 64 bit platform
else if("x64" >< osArch){
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");

}

foreach key (key_list)
{
   foreach item (registry_enum_keys(key:key))
   {
     if("Microsoft Money" >< registry_get_sz(key:key + item, item:"DisplayName"))
     {
      name = registry_get_sz(key:key + item, item:"DisplayName");

      InstallPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!InstallPath){
        InstallPath = "Couldn find the install location from registry";
      }

      ver = eregmatch(pattern:"Microsoft Money ([0-9]+)", string:name);
      if(ver[1] != NULL)
      {
        set_kb_item(name:"MS/Money/Version", value:ver[1]);

        ## build cpe and store it as host_detail
        cpe = build_cpe(value:ver[1], exp:"^([0-9]+)", base:"cpe:/a:microsoft:money:");
        if(isnull(cpe))
          cpe = "cpe:/a:microsoft:money";

        ## Register Product and Build Report
        build_report(app: "Microsoft Money", ver: ver[1], cpe: cpe, insloc: InstallPath);
      }

      ## 64 bit apps on 64 bit platform
      if(ver[1] != NULL && "x64" >< osArch && "Wow6432Node" >!< key)
      {
        set_kb_item(name:"MS/Money64/Version", value:ver[1]);

        ## build cpe and store it as host_detail
        cpe = build_cpe(value:ver[1], exp:"^([0-9]+)", base:"cpe:/a:microsoft:money:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:microsoft:money:x64";

        ## Register Product and Build Report
        build_report(app: "Microsoft Money", ver: ver[1], cpe: cpe, insloc: InstallPath);
      }
    }
  }
}
