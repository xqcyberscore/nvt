###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_detect_lin.nasl 7823 2017-11-20 08:54:04Z cfischer $
#
# Mozilla Firefox Version Detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# Modified to Detect All Installed Version
#  - By Sharath S <sharaths@secpod.com> on 2009-09-04 #4411
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
  script_oid("1.3.6.1.4.1.25623.1.0.800017");
  script_version("$Revision: 7823 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2008-10-07 14:21:23 +0200 (Tue, 07 Oct 2008)");
  script_name("Mozilla Firefox Version Detection (Linux)");

  script_tag(name : "summary" , value:"This script finds the Mozilla Firefox
  installed version on Linux and save the version in KB.");

  script_tag(name:"qod_type", value:"executable_version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
fox_sock = "";
foxName = "";
foxVer = "";

fox_sock = ssh_login_or_reuse_connection();
if(!fox_sock)
{
  exit(0);
}

foxName = find_file(file_name:"firefox", file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:fox_sock);

foreach binary_foxName (foxName)
{
  binary_name = chomp(binary_foxName);
  foxVer = get_bin_version(full_prog_name:binary_name, sock:fox_sock,
                           version_argv:"-v", ver_pattern:"Mozilla Firefox " +
                           "([0-9.]+([a-z0-9]+)?)");
  if(!isnull(foxVer[1]))
  {
    set_kb_item(name:"Firefox/Linux/Ver", value:foxVer[1]);
    replace_kb_item(name:"Firefox/Linux_or_Win/installed", value:TRUE);
    replace_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed", value:TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:foxVer[1], exp:"^([0-9.a-z]+)", base:"cpe:/a:mozilla:firefox:");
    if(isnull(cpe))
      cpe ="cpe:/a:mozilla:firefox";

    register_product(cpe:cpe, location:binary_foxName);

    log_message(data: build_detection_report(app: "Firefox", version:foxVer[1],
                                         install: binary_foxName,
                                         cpe: cpe,
                                         concluded: foxVer[1]));
  }
}
ssh_close_connection();
