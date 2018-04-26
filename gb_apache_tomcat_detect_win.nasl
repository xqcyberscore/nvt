###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_detect_win.nasl 9608 2018-04-25 13:33:05Z jschulte $
#
# Apache Tomcat Detection (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-06-03
# Updated according to CR57 and to support 32 and 64 bit.
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
  script_oid("1.3.6.1.4.1.25623.1.0.802377");
  script_version("$Revision: 9608 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-25 15:33:05 +0200 (Wed, 25 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-12 13:49:05 +0530 (Thu, 12 Jan 2012)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Apache Tomcat Detection (Windows)");


  script_tag(name : "summary" , value : "Detection of installed version of Apache Tomcat on Windows.

The script logs in via smb, searches for Apache Tomcat in the
registry and gets the version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

key = "SOFTWARE\Apache Software Foundation\Tomcat\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  tomPath = registry_get_sz(key:key + item, item:"InstallPath");
  tomVer = registry_get_sz(key:key + item, item:"Version");

  ## In latest application path and version are available inside one more key.
  ## that's why again Enumerating inside the key items.
  if(!tomVer)
  {
    key = key + item + "\";

    foreach innerItem (registry_enum_keys(key:key))
    {
      tomVer = registry_get_sz(key:key + innerItem, item:"Version");
      tomPath = registry_get_sz(key:key + innerItem, item:"InstallPath");
    }
  }

  if(!isnull(tomVer))
  {
    set_kb_item(name:"ApacheTomcat/Win/Ver", value:tomVer);

    cpe = build_cpe(value:tomVer, exp:"^([0-9.]+[a-z0-9]*)", base:"cpe:/a:apache:tomcat:");
    if(isnull(cpe))
      cpe = "cpe:/a:apache:tomcat";

    os_arch = get_kb_item("SMB/Windows/Arch");
    if(!os_arch)
    {
      exit(-1);
    }

    if("x64" >< os_arch)
    {
      set_kb_item(name:"ApacheTomcat64/Win/Ver", value:tomVer);

      cpe = build_cpe(value:tomVer, exp:"^([0-9.]+[a-z0-9]*)", base:"cpe:/a:apache:tomcat:x64:");
      if(isnull(cpe))
        cpe = "cpe:/a:apache:tomcat:x64";
    }
    register_product(cpe:cpe, location:tomPath);

    log_message(data: build_detection_report(app: "Apache Tomcat",
                                             version: tomVer,
                                             install: tomPath,
                                             cpe: cpe,
                                             concluded: tomVer));
  }
}
