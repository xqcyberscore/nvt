###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_sketchup_detect_macosx.nasl 6484 2017-06-29 09:15:46Z cfischer $
#
# Google SketchUp Version Detection (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902680");
  script_version("$Revision: 6484 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-06-29 11:15:46 +0200 (Thu, 29 Jun 2017) $");
  script_tag(name:"creation_date", value:"2012-05-21 15:49:33 +0530 (Mon, 21 May 2012)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Google SketchUp Version Detection (Mac OS X)");

  tag_summary =
"Detection of installed version of Google SketchUp.

The script logs in via ssh, searches for folder 'SketchUp.app' and
queries the related 'info.plist' file for string 'CFBundleVersion' via command
line option 'defaults read'.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 SecPod");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}


include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
gsVer = NULL;
sock = 0;
cpe = "";
ver = "";

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock) {
  exit(-1);
}

foreach ver (make_list("5", "6", "7", "8"))
{
  ## Get the version of Google SketchUp
  gsVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "Google\ SketchUp\ " + ver +"/SketchUp.app/" +
             "Contents/Info CFBundleVersion"));
  if(isnull(gsVer) || "does not exist" >< gsVer){
     continue;
  }

  ## Set the version in KB
  set_kb_item(name: "Google/SketchUp/MacOSX/Version", value:gsVer);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:gsVer, exp:"^([0-9.]+)", base:"cpe:/a:google:sketchup:");
  if(isnull(cpe))
    cpe='cpe:/a:google:sketchup';

  path = '/Applications/Google SketchUp ' + ver + '/SketchUp.app/';

  register_product(cpe:cpe, location:path);

  log_message(data: build_detection_report(app: "Google SketchUp",
                                           version:gsVer,
                                           install:path,
                                           cpe:cpe,
                                           concluded: gsVer));
}
