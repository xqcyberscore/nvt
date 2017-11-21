###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_desktop_board_bios_info_detect_lin.nasl 7823 2017-11-20 08:54:04Z cfischer $
#
# Desktop Boards BIOS Information Detection for Linux
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Updated Veerendra GG <veerendragg@secpod.com>
# Checking proper output in command output
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
  script_oid("1.3.6.1.4.1.25623.1.0.800163");
  script_version("$Revision: 7823 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_name("Desktop Boards BIOS Information Detection for Linux");

  script_tag(name: "summary" , value:
"Detection of installed version of Desktop Boards BIOS.

The script logs in via ssh and queries for the version using the command
line tool 'dmidecode'. Usually this command requires root privileges to
execute.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

SCRIPT_DESC = "Gather Boards BIOS related Information";

## Commands for BIOS Version and Vendor
bios_ver_cmd = "dmidecode -s bios-version";
bios_vend_cmd = "dmidecode -s bios-vendor";

## Commands for Base Board Version, Manufacturer and Product Name
base_board_ver_cmd = "dmidecode -s baseboard-version";
base_board_manu_cmd = "dmidecode -s baseboard-manufacturer";
base_board_prod_cmd = "dmidecode -s baseboard-product-name";

## Get BIOS Version and Vendor
bios_ver = ssh_cmd(socket:sock, cmd:bios_ver_cmd, timeout:120);
bios_vendor = ssh_cmd(socket:sock, cmd:bios_vend_cmd, timeout:120);

## Get Base Board Version, Manufacturer and Product Name
base_board_ver = ssh_cmd(socket:sock, cmd:base_board_ver_cmd, timeout:120);
base_board_manu = ssh_cmd(socket:sock, cmd:base_board_manu_cmd, timeout:120);
base_board_prod_name = ssh_cmd(socket:sock, cmd:base_board_prod_cmd, timeout:120);

report = "";

## Set BIOS Version
if(bios_ver != NULL && !(bios_ver =~ "command not found|dmidecode:|(p|P)ermission denied"))
{
  set_kb_item(name:"DesktopBoards/BIOS/Ver", value:chomp(bios_ver));
  report += "Desktop Boards BIOS version " + bios_ver + " was detected on the host\n";
  register_host_detail(name:"BIOSVersion", value:chomp(bios_ver), desc:SCRIPT_DESC);
}

## Set BIOS Vendor
if(bios_vendor != NULL && !(bios_vendor =~ "command not found|dmidecode:|(p|P)ermission denied"))
{
  set_kb_item(name:"DesktopBoards/BIOS/Vendor", value:chomp(bios_vendor));
  report += "Desktop Boards BIOS Vendor " + bios_vendor + " was detected on the host\n";
  register_host_detail(name:"BIOSVendor", value:chomp(bios_vendor), desc:SCRIPT_DESC);
}

## Set Base Board Version
if(base_board_ver != NULL && !(base_board_ver =~ "command not found|dmidecode:|(p|P)ermission denied"))
{
  set_kb_item(name:"DesktopBoards/BaseBoard/Ver", value:chomp(base_board_ver));
  report +="Desktop Boards Base Board version " + base_board_ver + " was detected on the host\n";
  register_host_detail(name:"BaseBoardVersion", value:chomp(base_board_ver), desc:SCRIPT_DESC);
}

## Set Base Board Manufacturer
if(base_board_manu != NULL && !(base_board_manu =~ "command not found|dmidecode:|(p|P)ermission denied"))
{
  set_kb_item(name:"DesktopBoards/BaseBoard/Manufacturer",
              value:chomp(base_board_manu));
  report += "Desktop Boards Base Board Manufacturer " + base_board_manu + " was detected on the host\n";
  register_host_detail(name:"BaseBoardManufacturer", value:chomp(base_board_manu), desc:SCRIPT_DESC);
}

## Set Base Board Product Name
if(base_board_prod_name != NULL && !(base_board_prod_name =~ "dmidecode:|command not found|(p|P)ermission denied"))
{
  set_kb_item(name:"DesktopBoards/BaseBoard/ProdName",
              value:chomp(base_board_prod_name));
  report +="Desktop Boards Base Board Product Name " + base_board_prod_name + " was detected on the host\n";
  register_host_detail(name:"BaseBoardProduct", value:chomp(base_board_prod_name), desc:SCRIPT_DESC);
}

if(report){
  log_message(data:report);
}
close(sock);
ssh_close_connection();
