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
  script_version("2019-06-03T11:22:42+0000");
  script_tag(name:"last_modification", value:"2019-06-03 11:22:42 +0000 (Mon, 03 Jun 2019)");
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
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Mozilla SeaMonkey Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

seaName = find_file(file_name:"seamonkey", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);
if(!seaName) {
  seaName = find_file(file_name:"iceape", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);
}

if(!seaName) {
  ssh_close_connection();
  exit(0);
}

foreach binary_seaName(seaName) {

  binary_name = chomp(binary_seaName);
  if(!binary_name)
    continue;

  seaVer = get_bin_version(full_prog_name:binary_name, version_argv:"-v", ver_pattern:"[0-9.]{3,}");
  if(seaVer[0]) {

    set_kb_item(name:"Seamonkey/Linux/Ver", value:seaVer[0]);
    set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed", value:TRUE);
    log_message(data:"Mozilla Seamonkey version " + seaVer[0] + " running at location " + binary_seaName + " was detected on the host");
    ssh_close_connection();

    cpe = build_cpe(value:seaVer[0], exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:mozilla:seamonkey:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    exit(0);
  }
}
ssh_close_connection();
