###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qt_detect.nasl 9347 2018-04-06 06:58:53Z cfischer $
#
# Qt Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "This script finds the installed Qt version and saves the version
  in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801234");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9347 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 08:58:53 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Qt Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Trolltech\")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

## Get Qt version from registry
foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("Qt OpenSource" >< name)
  {
    ver = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ver != NULL)
    {
      set_kb_item(name:"Qt/Ver", value:ver);
      log_message(data:"Qt OpenSource version " + ver +
                         " was detected on the host");
    }
  }
}
