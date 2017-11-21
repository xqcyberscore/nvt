###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_detect_lin.nasl 7823 2017-11-20 08:54:04Z cfischer $
#
# Google Chrome Version Detection (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# Updated By: Shakeel  <bshakeel@secpod.com> on 2013-10-10
# According to CR57 and new style script_tags.
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.801446";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7823 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Google Chrome Version Detection (Linux)");

  tag_summary =
"Detection of installed version of Google Chrome on Linux.

The script logs in via shh, extracts the version from the binary file
and set it in KB.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
chromeVer="";
chromePath="";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

chromePath = "/usr/bin/google-chrome";
## Trying to get version from rpm,deb packages
## For Fedora
buffer_rpm = get_kb_item("ssh/login/rpms");
if(buffer_rpm != NULL && buffer_rpm =~ "google-chrome")
{
  ## Grep for the version
  version = eregmatch(pattern:"google-chrome.?([a-zA-z])*.?([0-9.]+)", string:buffer_rpm);
  if(!isnull(version[2])){
         chromeVer = version[2];
  }
}

if(chromeVer == NULL)
{
  ## For ubuntu and debian
  buffer_deb = get_kb_item("ssh/login/packages");
  if(buffer_deb != NULL && buffer_deb =~ "google-chrome")
  {
    ## Grep for the string Google-Chrome
    google_match=egrep(pattern:"google-chrome.*",string:buffer_deb);
    if(!isnull(google_match))
    {
      ## Grep for the version
      version = eregmatch(pattern:"([0-9.]+)", string:google_match);
      if(!isnull(version)){
         chromeVer = version[1];
      }
    }
  }
}

if(chromeVer != NULL)
{
  ## Set KB item
  set_kb_item(name:"Google-Chrome/Linux/Ver", value:chromeVer);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:chromeVer, exp:"^([0-9.]+)", base:"cpe:/a:google:chrome:");
  if(isnull(cpe))
    cpe ="cpe:/a:google:chrome";

  register_product(cpe:cpe, location:chromePath, nvt:SCRIPT_OID);

  log_message(data: build_detection_report(app: "Google Chrome", version: chromeVer,
                                         install: chromePath,
                                         cpe: cpe,
                                         concluded: chromeVer));

}
close(sock);
ssh_close_connection();
