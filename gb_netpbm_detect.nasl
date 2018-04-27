###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netpbm_detect.nasl 9633 2018-04-26 14:07:08Z jschulte $
#
# NetPBM Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800470");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9633 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 16:07:08 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Netpbm Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 Greenbone Networks");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "summary" , value : "The script detects the installed version of Netpbm and sets the
  result into KB.");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Netpbm Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

grep = find_bin(prog_name:"grep", sock:sock);
grep = chomp(grep[0]);
garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("Netpbm [0-9.].\\+");

modName = find_file(file_name:"libnetpbm.so", file_path:"/",
                    useregex:TRUE, regexpar:"$", sock:sock);

foreach binaryName (modName)
{
  binaryName = chomp(binaryName);
  arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) +
        garg[3] + raw_string(0x22) + " " + binaryName;

  netpbmVer = get_bin_version(full_prog_name:grep, version_argv:arg,
                              ver_pattern:"Netpbm ([0-9.]+)", sock:sock);
  if(netpbmVer[1] != NULL)
  {
    set_kb_item(name:"NetPBM/Ver", value:netpbmVer[1]);
    log_message(data:"NetPBM version " + netpbmVer[1] +
                       " running at location " + binaryName +
                       " was detected on the host");

    cpe = build_cpe(value:netpbmVer[1], exp:"^([0-9.]+)", base:"cpe:/a:netpbm:netpbm:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
ssh_close_connection();
