###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qip_detect.nasl 9347 2018-04-06 06:58:53Z cfischer $
#
# QIP Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_summary = "This script detects the QIP version and saves the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800540");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9347 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 08:58:53 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("QIP Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800540";
SCRIPT_DESC = "QIP Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  qipName = registry_get_sz(key:key + item, item:"DisplayName");
  if(qipName =~ "QIP ([0-9]+)")
  {
    qipPath = registry_get_sz(key:key + item, item:"UninstallString");
    if(qipPath == NULL){
      exit(0);
    }
    qipPath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:qipPath);
    qipPath = qipPath - "unqip.exe" - "unins000.exe" + "qip.exe";

    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:qipPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:qipPath);
    qipVer = GetVer(file:file, share:share);

    if(qipVer)
    {
      set_kb_item(name:"QIP/Version", value:qipVer);
      log_message(data:"QIP version " + qipVer + 
                         " running at location " + qipPath +
                         " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:qipVer, exp:"^(8\.0\..*)", base:"cpe:/a:qip:qip:2005");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
    exit(0);
  }
}
