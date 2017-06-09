###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_creative_cloud_detect_macosx.nasl 6065 2017-05-04 09:03:08Z teissa $
#
# Adobe Creative Cloud Version Detection (Mac OS X)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807671");
  script_version("$Revision: 6065 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-04 11:03:08 +0200 (Thu, 04 May 2017) $");
  script_tag(name:"creation_date", value:"2016-04-14 18:14:10 +0530 (Thu, 14 Apr 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Creative Cloud Version Detection (Mac OS X)");

  script_tag(name : "summary" , value : "Detection of installed version of
  Adobe Creative.

  The script logs in via ssh, searches for folder 'Adobe Creative Cloud' and
  queries the related 'info.plist' file for string 'CFBundleVersion' via command
  line option 'defaults read'.");

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
ediVer = "";
sock = "";
cpe  = "";

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(-1);
}

## Get the version of Creative cloud
ediVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
            "Adobe\ Creative\ Cloud/Adobe\ Creative\ Cloud/Contents/Info " +
            "CFBundleShortVersionString"));

## Close Socket
close(sock);

## Exit if version not found
if(isnull(ediVer) || "does not exist" >< ediVer){
  exit(0);
}

## Set the version in KB
set_kb_item(name: "AdobeCreativeCloud/MacOSX/Version", value:ediVer);

## build cpe and store it as host_detail
cpe = build_cpe(value:ediVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:creative_cloud:");
if(isnull(cpe))
  cpe='cpe:/a:adobe:creative_cloud';

register_product(cpe:cpe, location:'/Applications/Adobe Creative Clouds');

log_message(data: build_detection_report(app: "Adobe Creative Clouds",
                                         version: ediVer,
                                         install: "/Applications/Adobe Creative Clouds/",
                                         cpe: cpe,
                                         concluded: ediVer));
exit(0);
