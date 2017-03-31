###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_greenbrowser_detect_win.nasl 5040 2017-01-19 14:01:58Z cfi $
#
# GreenBrowser Version Detection (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803066");
  script_version("$Revision: 5040 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-19 15:01:58 +0100 (Thu, 19 Jan 2017) $");
  script_tag(name:"creation_date", value:"2012-12-06 17:22:08 +0530 (Thu, 06 Dec 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("GreenBrowser Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"Detection of installed version of GreenBrowser.

  The script logs in via smb, searches for GreenBrowser in the registry and
  gets the version from GreenBrowser.exe file using 'InstallLocation' string in registry");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

key = "";
greenbName = "";
greenbPath = "";
greenbVer = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item( registry_enum_keys( key:key ) )
{
  greenbName = registry_get_sz(key:key + item, item:"DisplayName");
  if("GreenBrowser" >< greenbName)
  {
    greenbPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(greenbPath)
    {

     greenbPath = greenbPath + "GreenBrowser.exe";
     greenbVer = GetVersionFromFile(file: greenbPath,verstr:"prod");

      if(greenbVer)
      {
        ## Set the KB item
        set_kb_item(name:"GreenBrowser/Win/Ver", value: greenbVer);

        ## Build CPE
        cpe = build_cpe(value: greenbVer, exp:"^([0-9.]+)", base:"cpe:/a:morequick:greenbrowser:");
        if(isnull(cpe))
          cpe = 'cpe:/a:morequick:greenbrowser';

        register_product(cpe:cpe, location:greenbPath);

        log_message(data: build_detection_report(app: greenbName, version: greenbVer,
                                                 install: greenbPath, cpe:cpe, concluded:greenbVer));

        exit(0);
      }
    }
  }
}
