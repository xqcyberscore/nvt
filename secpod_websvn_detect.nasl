###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_websvn_detect.nasl 2750 2016-03-01 09:31:55Z antu123 $
#
# WebSVN script version detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated by: Kashinath T <tkashinath@secpod.com>
# Updated to set the kb item. 
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900440");
  script_version("$Revision: 2750 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-01 10:31:55 +0100 (Tue, 01 Mar 2016) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("WebSVN version detection");
 
  script_tag(name:"summary" , value:"The script detects the version of WebSVN
  and sets the result in KB.");
  
  script_summary("Set the KB for the Version of WebSVN");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

websvnPort = get_kb_item("Services/www");
if(!websvnPort){
  exit(0);
}

if(!can_host_php(port:websvnPort)) exit(0);


## Function to Register Product and Build report
function build_report(app, ver, cpe, loc, con)
{
  set_kb_item(name:"www/" + websvnPort + "/WebSVN", value:svnVer);
  set_kb_item(name:"WebSVN/Installed", value:TRUE);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:svnVer, exp:"^([0-9.]+)", base:"cpe:/a:tigris:websvn:");
  if(isnull(cpe)){
       cpe = "cpe:/a:tigris:websvn";
  }
  
  register_product(cpe:cpe, location:loc);

  log_message(data: build_detection_report(app: app,
                                           version: ver,
                                           install: loc,
                                           cpe: cpe,
                                           concluded: con));
}

foreach dir (make_list_unique("/", "/websvn", "/svn", cgi_dirs(port:websvnPort)))
{
  if( dir == "/" ) dir = "";

  sndReq = http_get(item:string(dir, "/index.php"), port:websvnPort);
  rcvRes = http_keepalive_send_recv(port:websvnPort, data:sndReq);
 
  if("WebSVN" >!< rcvRes)
  {
    sndReq = http_get(item:string(dir, "/listing.php"), port:websvnPort);
    rcvRes = http_keepalive_send_recv(port:websvnPort, data:sndReq);
  }

  if("WebSVN" >< rcvRes && "Subversion" >< rcvRes)
  {
    svnVer = eregmatch(pattern:"WebSVN ([0-9.]+)", string:rcvRes);
    if(svnVer[1] == NULL){
       svnVer = "Unknown";
    } 
    else{
      svnVer = svnVer[1];
    }

    build_report(app:"WebSVN", ver:svnVer, cpe:cpe, loc:dir, con:svnVer);
    exit(0);
  }
}
