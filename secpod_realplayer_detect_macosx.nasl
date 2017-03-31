###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_realplayer_detect_macosx.nasl 5505 2017-03-07 10:00:18Z teissa $
#
# RealNetworks RealPlayer Version Detection (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Thanga Prakash S <tprakash@secpod.com> on 2013-08-29
# Updated to get full Version with Build.
# Updated according to CR57 and new style script_tags.
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902622";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5505 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-07 11:00:18 +0100 (Tue, 07 Mar 2017) $");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("RealNetworks RealPlayer Version Detection (Mac OS X)");

  tag_summary =
"Detection of installed version of RealPlayer on MAC.

The script logs in via ssh, gets the version by using a command and set
it in the KB item.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2011 SecPod");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  exit(0);
}


include("cpe.inc");
include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

## variable initialization
sock = "";
realVer = "";
fullVer = "";

## Function to Build report
function build_report(ver)
{
  insloc = "Unable to find the install Location.";

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:realnetworks:realplayer:");
  if(isnull(cpe))
    cpe = "cpe:/a:realnetworks:realplayer";

  register_product(cpe:cpe, location:insloc, nvt:SCRIPT_OID);

  log_message(data: build_detection_report(app: "RealPlayer",
                                           version: ver,
                                           install: insloc,
                                           cpe: cpe,
                                           concluded: ver));
  exit(0);
}

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Checking for Mac OS X
if (!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

## Get the version of RealPlayer
realVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
               "RealPlayer.app/Contents/Info CFBundleShortVersionString"));

## Get the version of RealPlayer
fullVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
               "RealPlayer.app/Contents/Info HelixVersion"));

## Close Socket
close(sock);

## Exit if version not found
if(isnull(realVer) || "does not exist" >< realVer){
  exit(0);
}

## Set the version in KB
set_kb_item(name: "RealPlayer/MacOSX/Version", value:realVer);

if(fullVer)
{
  set_kb_item(name: "RealPlayer/MacOSX/FullVer", value:fullVer);
  build_report(ver: fullVer);
}

build_report(ver: realVer);
