###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_server_detect.nasl 4724 2016-12-09 09:02:10Z antu123 $
#
# Apple OS X Server Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810231");
  script_version("$Revision: 4724 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-12-09 10:02:10 +0100 (Fri, 09 Dec 2016) $");
  script_tag(name:"creation_date", value:"2016-12-05 14:52:33 +0530 (Mon, 05 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple OS X Server Version Detection");
  script_tag(name : "summary" , value : "Detection of installed version of
  Apple OS X Server on MAC OS X.

  The script logs in via ssh, searches for folder 'Server.app' and
  queries the related 'info.plist' file for string 'CFBundleVersion' via
  command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}


include("cpe.inc");
include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

## Variable Initialization
serVer = "";
sock = "";
cpe  = "";

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(-1);
}

name = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                    "Server.app/Contents/Info " +
                    "CFBundleName"));

##Confirm Application
if("Server" >< name)
{
  ## Get the version of apple macosx server
  serVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                     "Server.app/Contents/Info " +
                     "CFBundleShortVersionString"));

  if(!serVer)
  {
    ## Get the version from version.plist
    serVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                     "Server.app/Contents/version " +
                     "CFBundleShortVersionString"));
  }

  ## Close Socket
  close(sock);

  ## Exit if version not found
  if(isnull(serVer) || "does not exist" >< serVer){
   exit(0);
  }

  ## Set the version in KB
  set_kb_item(name: "Apple/OSX/Server/Version", value:serVer);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:serVer, exp:"^([0-9.]+)", base:"cpe:/o:apple:os_x_server:");
  if(isnull(cpe))
    cpe='cpe:/o:apple:os_x_server';

  register_product(cpe:cpe, location:'/Applications/Server.app');

  log_message(data: build_detection_report(app: "Apple OS X Server",
                                           version: serVer,
                                           install: "/Applications/Server.app/",
                                           cpe: cpe,
                                           concluded: serVer));
  exit(0);
}
