###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ston3d_prdts_detect_lin.nasl 9633 2018-04-26 14:07:08Z jschulte $
#
# StoneTrip Ston3D Standalone Player Version Detection (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800575");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9633 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 16:07:08 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("StoneTrip Ston3D Standalone Player Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "summary" , value : "This script detects the installed version of StoneTrip Ston3D
  Standalone Player and sets the result in KB.");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "StoneTrip Ston3D Standalone Player Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

grep = find_bin(prog_name:"grep", sock:sock);
grep = chomp(grep[0]);

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("Standalone Engine [0-9.]\\+");

sapName = find_file(file_name:"S3DEngine_Linux", file_path:"/",
                      useregex:TRUE, regexpar:"$", sock:sock);
if(sapName != NULL)
{
  foreach binaryName (sapName)
  {
    binaryName = chomp(binaryName);
    if(islocalhost())
    {
      garg[4] = binaryName;
      arg = garg;
    }
    else
    {
      arg = garg[0]+" "+garg[1]+" "+garg[2]+" "+
            raw_string(0x22)+garg[3]+raw_string(0x22)+" "+binaryName;
    }

    sapVer = get_bin_version(full_prog_name:grep, version_argv:arg, sock:sock,
                               ver_pattern:"([0-9.]+)");
    if(sapVer[1] != NULL)
    {
      set_kb_item(name:"Ston3D/Standalone/Player/Lin/Ver", value:sapVer[1]);
      log_message(data:"StoneTrip Ston3D Standalone Player version " + sapVer[1] +
                    " running at location " + binaryName + " was detected on the host");

      cpe = build_cpe(value:sapVer[1], exp:"^([0-9.]+)", base:"cpe:/a:stonetrip:s3dplayer_standalone:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

      break;
    }
  }
}
