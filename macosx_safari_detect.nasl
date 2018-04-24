###################################################################
# OpenVAS Vulnerability Test
# $Id: macosx_safari_detect.nasl 9584 2018-04-24 10:34:07Z jschulte $
#
# Apple Safari Detect Script (Mac OS X)
#
# LSS-NVT-2010-009
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Update By:  Shakeel <bshakeel@secpod.com> on 2013-11-05
# According to CR57 and new style script_tags.
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.102021";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 9584 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-24 12:34:07 +0200 (Tue, 24 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-04-06 10:41:02 +0200 (Tue, 06 Apr 2010)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple Safari Detect Script (Mac OS X)");

  tag_summary =
"Detection of installed version of Apple Safari on Mac OS X.

The script logs in via ssh, searches for folder 'Safari.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
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
ver="";
sock="";
cpe="";

sock = ssh_login_or_reuse_connection();
if(!sock) {
  exit(-1);
}

## Get the version
ver = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                 "Safari.app/Contents/Info CFBundleShortVersionString"));

## Exit if version not found
if(isnull(ver) || "does not exist" >< ver){
  log_message(data:"exiting" +ver);
  exit(0);
}
set_kb_item(name: "AppleSafari/MacOSX/Version", value:ver);

## build cpe and store it as host_detail
cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:apple:safari:");
if(isnull(cpe))
  cpe='cpe:/a:apple:safari';

register_product(cpe:cpe, location:'/Applications/Safari.app');

log_message(data: build_detection_report(app: "Safari", version: ver,
                                         install: "/Applications/Safari.app",
                                         cpe: cpe,
                                         concluded: ver));
