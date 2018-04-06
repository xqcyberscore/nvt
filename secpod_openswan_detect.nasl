###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openswan_detect.nasl 9347 2018-04-06 06:58:53Z cfischer $
#
# Openswan Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_summary = "This script detects the installed version of Openswan and
  sets the reuslt in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900387");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9347 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 08:58:53 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Openswan Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("version_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900387";
SCRIPT_DESC = "Openswan Version Detection";

oswan_sock = ssh_login_or_reuse_connection();
if(!oswan_sock){
  exit(0);
}

paths = find_bin(prog_name:"ipsec", sock:oswan_sock);
foreach swanBin (paths)
{
  oswanVer = get_bin_version(full_prog_name:chomp(swanBin),
                             sock:oswan_sock, version_argv:"--version",
                             ver_pattern:"Openswan U(([0-9.]+)(rc[0-9])?)");
  if(oswanVer[1] != NULL)
  {
    set_kb_item(name:"Openswan_or_StrongSwan/Lin/Installed", value:TRUE);
    set_kb_item(name:"Openswan/Ver", value:oswanVer[1]);
    log_message(data:"Openswan version " + oswanVer[1] + 
                       " was detected on the host");
    ssh_close_connection();

    ## build cpe and store it as host_detail
    cpe = build_cpe(value: oswanVer[1], exp:"^([0-9.]+)(rc[0-9])?",base:"cpe:/a:openswan:openswan:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    exit(0);
  }
}
ssh_close_connection();
