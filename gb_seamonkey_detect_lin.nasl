###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Seamonkey Version Detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800019");
  script_version("2019-08-20T12:18:54+0000");
  script_tag(name:"last_modification", value:"2019-08-20 12:18:54 +0000 (Tue, 20 Aug 2019)");
  script_tag(name:"creation_date", value:"2008-10-07 14:21:23 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Mozilla SeaMonkey Version Detection (Linux)");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script finds the Mozilla SeaMonkey installed version on
  Linux and saves the version in KB.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

seaName = find_file(file_name:"seamonkey", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);
if(!seaName)
  seaName = find_file(file_name:"iceape", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);

if(!seaName) {
  ssh_close_connection();
  exit(0);
}

baseCPE = "cpe:/a:mozilla:seamonkey:";

foreach binary_seaName(seaName) {

  binary_name = chomp(binary_seaName);
  if(!binary_name)
    continue;

  #Examples for versions:
  #1.0 Alpha
  #2.0 RC 2
  #2.0.14
  #2.49.4
  #Returned version from binary: Mozilla SeaMonkey 2.49.4
  seaVer = get_bin_version(full_prog_name:binary_name, version_argv:"-v", ver_pattern:"^Mozilla\sSeaMonkey\s([0-9]+\.[0-9.]+(\s(RC\s[0-9]+|Alpha|Beta))?)$");
  if(seaVer[1]) {

    set_kb_item(name:"Seamonkey/Linux/Ver", value:seaVer[1]);
    set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed", value:TRUE);

    cpeVer = str_replace(string:seaVer[1], find:" ", replace:".");
    CPE = baseCPE + cpeVer;

    register_product(cpe:CPE, location:binary_seaName, service:"ssh-login", port:0);

    log_message(data:build_detection_report(app:"Mozilla SeaMonkey (Linux)",
                                            version:seaVer[1],
                                            install:binary_seaName,
                                            cpe:CPE,
                                            concluded:seaVer[0]));
    break;
  }
}

ssh_close_connection();
exit(0);