###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Version Detection (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800209");
  script_version("2019-07-05T06:51:10+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-07-05 06:51:10 +0000 (Fri, 05 Jul 2019)");
  script_tag(name:"creation_date", value:"2008-12-19 13:40:09 +0100 (Fri, 19 Dec 2008)");
  script_name("Microsoft Internet Explorer Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "smb_registry_access.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of
  Microsoft Internet Explorer.

  The script logs in via smb, detects the version of Microsoft Internet Explorer
  on remote host and sets the KB.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

ver_key = "SOFTWARE\Microsoft\Internet Explorer";
if(!registry_key_exists(key:ver_key))
  exit(0);

ver_item = "svcVersion";
if(!ver = registry_get_sz(item:ver_item, key:ver_key, no_cache:TRUE)) {
  # nb: Try the same key again to avoid detecting a wrong version on e.g. network problems
  if(!ver = registry_get_sz(item:ver_item, key:ver_key)) {
    ver_item = "Version";
    ver = registry_get_sz(item:ver_item, key:ver_key);
    if(ver)
      concl_item = ver_item;
  } else {
    concl_item = ver_item;
  }
} else {
  concl_item = ver_item;
}

ins_loc  = "unknown";
exe_key  = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE";
exe_item = "Path";
exe_path = registry_get_sz(key:exe_key, item:exe_item);
if(exe_path) {
  rep_path = exe_path;
  # nb: The path contains a trailing ";" like e.g. C:\Program Files\Internet Explorer;
  exe_path = ereg_replace(pattern:";$", string:exe_path, replace:"");
  ins_loc  = exe_path;
}

if(ver) {

  concluded  = "Version Registry-Key: " + ver_key + "!" + concl_item + '\n';
  concluded += "Registry-Key Content: " + ver;
  if(exe_path) {
    concluded += '\n';
    concluded += "Path Registry-Key:    " + exe_key + "!" + exe_item + '\n';
    concluded += "Registry-Key Content: " + rep_path;
  }

  set_kb_item(name:"MS/IE/Version", value:ver);
  set_kb_item(name:"MS/IE/Installed", value:TRUE);
  set_kb_item(name:"MS/IE_or_EDGE/Installed", value:TRUE);
  register_and_report_cpe(app:"Microsoft Internet Explorer", ver:ver, base:"cpe:/a:microsoft:ie:", expr:"^([0-9.]+)", insloc:ins_loc, concluded:concluded);
  exit(0);
}

if(exe_path && !ver) {

  file_name = "iexplore.exe";
  ver = fetch_file_version(sysPath:exe_path, file_name:file_name);
  if(ver) {

    concluded  = "File-Name:            " + exe_path + "\" + file_name + '\n';
    concluded += "File-Version:         " + ver + '\n';
    concluded += "Path Registry-Key:    " + exe_key + "!" + exe_item + '\n';
    concluded += "Registry-Key Content: " + rep_path;

    set_kb_item(name:"MS/IE/EXE/Ver", value:ver);
    set_kb_item(name:"MS/IE/Installed", value:TRUE);
    set_kb_item(name:"MS/IE_or_EDGE/Installed", value:TRUE);
    register_and_report_cpe(app:"Microsoft Internet Explorer", ver:ver, base:"cpe:/a:microsoft:ie:", expr:"^([0-9.]+)", insloc:exe_path, concluded:concluded);
  }
}

exit(0);