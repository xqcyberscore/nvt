###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sonatype_nexus_detect.nasl 3746 2016-07-22 13:22:46Z mime $
#
# Sonatype Nexus OSS/Pro Version Detection
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805324");
  script_version("$Revision: 3746 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-07-22 15:22:46 +0200 (Fri, 22 Jul 2016) $");
  script_tag(name:"creation_date", value:"2015-01-20 13:00:12 +0530 (Tue, 20 Jan 2015)");
  script_name("Sonatype Nexus OSS/Pro Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  Sonatype Nexus.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_summary("Set Version of Sonatype Nexus in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variables Initialization
nexusPort  = "";
dir  = "";
sndReq = "";
rcvRes = "";
nexusVer = "";
cpe = "";
url = "";
installed = 0;

##Sonatype Nexus Port
nexusPort = get_http_port(default:8081);

banner = get_http_banner(port:nexusPort);

## Confirm the server from banner
if(banner && "erver: Nexus" >< banner) {

  installed = 1;
  version = "unknown";
  nexusVer = eregmatch(pattern:"Server: Nexus.([0-9.]+(-[0-9]+)?)", string:banner, icase:TRUE);
  if(nexusVer[1] != NULL) {
    version = nexusVer[1];
    install = "/";
  }
}

if(!nexusVer) {
  foreach dir (make_list_unique("/", "/nexus",  cgi_dirs(port:nexusPort))) {

    install = dir;
    if(dir == "/") dir = "";

    ## if version is not available in banner request for '/#welcome' page
    sndReq = http_get(item: dir + "/#welcome", port:nexusPort);
    rcvRes = http_keepalive_send_recv(port:nexusPort, data:sndReq);

    ##Confirm Application with '/#welcome' page
    if(rcvRes && (">Sonatype Nexus<" >< rcvRes ||
       ">Sonatype Nexus Professional<" >< rcvRes))
    {
      installed = 1;
      version = "unknown";
      nexusVer = eregmatch(pattern:"nexusVersion=([0-9.]+(-[0-9]+)?)", string:rcvRes);
      if(nexusVer[1] != NULL){
        version = nexusVer[1];
      }
    }
  }
}

if(installed)
{
  # version will be in this format nexusVer = "2.11.1-01"
  # for replacing '-' with '.'
  version = str_replace(string:version, find:"-", replace:".");

  ##Set the KB
  set_kb_item(name:"www/" + nexusPort + "/nexus", value:version);
  set_kb_item(name:"nexus/installed",value:TRUE);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:sonatype:nexus:");
  if(isnull(cpe))
    cpe = "cpe:/a:sonatype:nexus";

  ##Register Product and Build Report
  register_product(cpe:cpe, location:install, port:nexusPort);
  log_message(data: build_detection_report(app: "Sonatype Nexus",
                                           version:version,
                                           install:install,
                                           cpe:cpe,
                                           concluded:nexusVer[0]),
                                           port:nexusPort);
}
