#############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_detect_macosx.nasl 6065 2017-05-04 09:03:08Z teissa $
#
# Google Chrome Version Detection (MacOSX)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Updated by: Rachana Shetty <srachana@secpod.com> on 2011-12-09
# - Updated the detect pat to escape the space.
#
# Updated By:  Shakeel <bshakeel@secpod.com> on 2013-10-08
# According to cr57 and new style script_tags.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802318";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6065 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-04 11:03:08 +0200 (Thu, 04 May 2017) $");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Google Chrome Version Detection (MacOSX)");

  tag_summary =
"Detection of installed version of Google Chrome on Mac OS X.

The script logs in via ssh, searches for folder 'Google Chrome.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
chromeVer="";
sock="";
cpe="";

sock = ssh_login_or_reuse_connection();
if(!sock) {
  exit(-1);
}

## Get the version Google Chrome
chromeVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "Google\ Chrome.app/Contents/Info CFBundleShortVersionString"));

## Close Socket
close(sock);

## Exit if version not found
if(isnull(chromeVer) || "does not exist" >< chromeVer){
  exit(0);
}

## Set the version in KB
set_kb_item(name: "GoogleChrome/MacOSX/Version", value:chromeVer);

## build cpe and store it as host_detail
cpe = build_cpe(value:chromeVer, exp:"^([0-9.]+)", base:"cpe:/a:google:chrome:");
if(isnull(cpe))
  cpe='cpe:/a:google:chrome';

register_product(cpe:cpe, location:'/Applications/Google Chrome.app', nvt:SCRIPT_OID);

log_message(data: build_detection_report(app: "Google Chrome", version: chromeVer,
                                         install: "/Applications/Google Chrome.app",
                                         cpe: cpe,
                                         concluded: chromeVer));


