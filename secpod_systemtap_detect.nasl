###############################################################################
# OpenVAS Vulnerability Test
#
# SystemTap Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901036");
  script_version("2019-09-27T05:58:04+0000");
  script_tag(name:"last_modification", value:"2019-09-27 05:58:04 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SystemTap Detection (SSH)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of SystemTap.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = find_bin(prog_name:"stap", sock:sock);
foreach systemtapbin(paths) {

  systemtapbin = chomp(systemtapbin);
  if(!systemtapbin)
    continue;

  vers = get_bin_version(full_prog_name:systemtapbin, sock:sock, version_argv:"-V", ver_pattern:"version ([0-9.]+)");

  if(!isnull(vers[1]) && "SystemTap" >< vers) {

    set_kb_item(name:"SystemTap/Ver", value:vers[1]);

    cpe = build_cpe(value:vers[1], exp:"^([0-9.]+)", base:"cpe:/a:systemtap:systemtap:");
    if(!cpe)
      cpe = "cpe:/a:systemtap:systemtap";

    register_product(cpe:cpe, location:systemtapbin, port:0, service:"ssh-login");

    log_message(data:build_detection_report(app:"SystemTap", version:vers[1], install:systemtapbin, cpe:cpe, concluded:vers[0]),
                port:0);

  }
}
ssh_close_connection();
