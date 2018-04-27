###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icq_toolbar_detect.nasl 9633 2018-04-26 14:07:08Z jschulte $
#
# ICQ Toolbar Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800693");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9633 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 16:07:08 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ICQ Toolbar version detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : "This script detects the installed version of ICQ Toolbar and
  sets the result in KB.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "ICQ Toolbar version detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

Key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:Key)){
    exit(0);
}

foreach item (registry_enum_keys(key:Key))
{
  icqName = registry_get_sz(key:Key + item, item:"DisplayName");
  if("ICQ" >< icqName)
  {
    path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\",
                                                    item:"ProgramFilesDir");

    foreach file (make_list("\ICQToolbar\version.txt","\ICQ6Toolbar\version.txt"))
    {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path + file);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path + file );

      icqVer = read_file(share:share, file:file, offset:0, count:25);
      icqVer = ereg_replace(pattern:"[-| ]", replace:".", string:icqVer);
      if(icqVer)
      {
        set_kb_item(name:"ICQ/Toolbar/Ver", value:icqVer);
        log_message(data:"ICQ Toolbar version " + icqVer + " was detected on the host");

        cpe = build_cpe(value:icqVer, exp:"^([0-9.]+)", base:"cpe:/a:icq:icq_toolbar:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

      }
    }
  }
}
