###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird Version Detection (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800018");
  script_version("2019-08-20T12:18:54+0000");
  script_tag(name:"last_modification", value:"2019-08-20 12:18:54 +0000 (Tue, 20 Aug 2019)");
  script_tag(name:"creation_date", value:"2008-10-07 14:21:23 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Mozilla Thunderbird Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script retrieves Mozilla Thunderbird Version and
  saves it in KB.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

birdName = find_file(file_name:"thunderbird", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);
if(!birdName) {
  ssh_close_connection();
  exit(0);
}

baseCPE = "cpe:/a:mozilla:thunderbird:";

foreach binary_birdName(birdName) {

  binary_name = chomp(binary_birdName);
  if(!binary_name)
    continue;

  #Examples for versions:
  #9.0a1
  #10.0.3esr
  #11.0
  #24.0b2
  #1.5 RC1
  #1.0
  #Example of returned version: Thunderbird 60.8.0
  birdVer = get_bin_version(full_prog_name:binary_name, version_argv:"-v", ver_pattern:"Thunderbird\s([0-9]+\.[0-9.]+(\s?[a-zA-Z]+[0-9]*)?)", sock:sock);
  if(birdVer[1]) {

    set_kb_item(name:"Thunderbird/Linux/Ver", value:birdVer[1]);
    set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed", value:TRUE);

    cpeVer = str_replace(string:birdVer[1], find:" ", replace:".");
    CPE = baseCPE + cpeVer;

    register_product(cpe:CPE, location:binary_birdName, service:"ssh-login", port:0);

    log_message(data:build_detection_report(app:"Mozilla Thunderbird (Linux)",
                                            version:birdVer[1],
                                            install:binary_birdName,
                                            cpe:CPE,
                                            concluded:birdVer[0]));
    break;
  }
}

ssh_close_connection();
exit(0);
