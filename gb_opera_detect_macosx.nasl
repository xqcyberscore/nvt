###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_detect_macosx.nasl 9584 2018-04-24 10:34:07Z jschulte $
#
# Opera Browser Version Detection (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Update By: Shakeel <bshakeel@secpod.com> on 2013-10-03
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802142";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 9584 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-24 12:34:07 +0200 (Tue, 24 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Opera Browser Version Detection (Mac OS X)");

  tag_summary =
  "Detection of installed version of Opera on Mac OS X.

The script logs in via ssh, searches for folder 'Opera.app' and
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
operaVer = "";
sock = "";
cpe  = "";

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(-1);
}

## Get the version of Opera
operaVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
            "Opera.app/Contents/Info CFBundleShortVersionString"));

## Close Socket
close(sock);

## Exit if version not found
if(isnull(operaVer) || "does not exist" >< operaVer){
  exit(0);
}

## Set the version in KB
set_kb_item(name: "Opera/MacOSX/Version", value:operaVer);

## build cpe and store it as host_detail
cpe = build_cpe(value:operaVer, exp:"^([0-9.]+)", base:"cpe:/a:opera:opera_browser:");
if(isnull(cpe))
  cpe='cpe:/a:opera:opera_browser';

register_product(cpe:cpe, location:'/Applications/Opera.app');

log_message(data: build_detection_report(app: "Opera", version: operaVer,
                                         install: "/Applications/Opera.app",
                                         cpe: cpe,
                                         concluded: operaVer));
