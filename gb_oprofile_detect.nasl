###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oprofile_detect.nasl 6032 2017-04-26 09:02:50Z teissa $
#
# OProfile Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "This script finds the installed OProfile version and saves
  the result in KB.";

if(description)
{
  script_id(802109);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 6032 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-26 11:02:50 +0200 (Wed, 26 Apr 2017) $");
  script_tag(name:"creation_date", value:"2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OProfile Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Service detection");
  script_mandatory_keys("login/SSH/Linux");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

opName = find_bin(prog_name:"oprofiled", sock:sock);
foreach binary_opName (opName)
{
  opVer = get_bin_version(full_prog_name:chomp(binary_opName),
                            version_argv:"-v",
                            ver_pattern:"oprofile ([0-9.]+)", sock:sock);
  if(opVer[1])
  {
    set_kb_item(name:"OProfile/Ver", value:opVer[1]);
    log_message(data:"OProfile version " + opVer[1] + " running at location "
                          + binary_opName + " was detected on the host");
  }
}
ssh_close_connection();
