###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_itunes_detect_macosx.nasl 6484 2017-06-29 09:15:46Z cfischer $
#
# Apple iTunes Version Detection (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.902717";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6484 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"last_modification", value:"$Date: 2017-06-29 11:15:46 +0200 (Thu, 29 Jun 2017) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_name("Apple iTunes Version Detection (Mac OS X)");

  tag_summary =
"This script finds the installed product version of Apple iTunes
on Mac OS X and sets the result in KB";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}


include("cpe.inc");
include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Checking for Mac OS X
if(!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

## Get the version of Apple iTunes
itunesVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                  "iTunes.app/Contents/Info CFBundleShortVersionString"));

## Close Socket
close(sock);

## Exit if version not found
if(isnull(itunesVer) || "does not exist" >< itunesVer){
  exit(0);
}

## Set the version in KB
set_kb_item(name: "Apple/iTunes/MacOSX/Version", value:itunesVer);


## Build cpe
cpe = build_cpe(value:itunesVer, exp:"^([0-9.]+)", base:"cpe:/a:apple:itunes:");
if(isnull(cpe))
  cpe = 'cpe:/a:apple:itunes';

insPath = "/Applications/iTunes.app";

register_product(cpe:cpe, location:insPath, nvt:SCRIPT_OID);

log_message(data: build_detection_report(app: "Apple iTunes",
                                         version: itunesVer,
                                         install: insPath,
                                         cpe: cpe,
                                         concluded: itunesVer));
