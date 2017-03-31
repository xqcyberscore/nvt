###############################################################################
# OpenVAS Vulnerability Test
# $Id: invision_power_board_detect.nasl 2837 2016-03-11 09:19:51Z benallard $
#
# IP.Board Detection
#
# Authors:
# Michael Meyer
#
# Updated to include upload directory and set multiple versions.
#  - By Nikita MR <rnikita@secpod.com> on 2009-11-20 15:25:02Z
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# Updated to detect IPB versions 2.3.3 and 2.3.5
#   -By Sharath S <sharaths@secpod.com> on 2009-04-09
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

tag_summary = "Detection of IP.Board.
                     
The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100107";

if (description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 2837 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
  script_tag(name:"creation_date", value:"2009-04-06 18:10:45 +0200 (Mon, 06 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("IP.Board Detection");

  script_summary("Checks for the presence of IP.Board");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);

if(!get_port_state(port)){
  exit(0);
}

if(!can_host_php(port:port)){
  exit(0);
}

dirs = make_list("/forum","/board","/ipb","/community", "/", cgi_dirs());
foreach mdir (dirs)
{
  foreach dir (make_list("/", "/upload/"))
  {
    url = string(mdir, dir, "index.php");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if("</html>" >!< buf)
    {
      req = string("GET ", mdir, dir, "index.php", "\r\n",
                   "Host: ", get_host_name(), "\r\n\r\n");
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    }

    if(egrep(pattern:"Powered [Bb]y ?(<a [^>]+>)?(Invision Power Board|IP.Board)",
             string: buf, icase: TRUE) )
    {
      if(strlen(mdir) > 0){
        install=mdir;
      }
      else{
        install=string("/");
      }

      vers = string("unknown");

      ### try to get version
      version = eregmatch(pattern:"v*([0-9.]+[a-zA-Z ]*) &copy;.*[0-9]{4}.*IPS.*",
                          string:buf, icase:TRUE);

      if(!isnull(version[1])){
        vers=version[1];
      }

      tmp_version = string(vers," under ",install);
      set_kb_item(name:string("www/", port, "/invision_power_board"), value:tmp_version);
      set_kb_item(name:"invision_power_board/installed", value:TRUE);
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:invision_power_services:invision_power_board:");
      if(isnull(cpe))
        cpe = 'cpe:/a:invision_power_services:invision_power_board';

      register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);

      log_message(data: build_detection_report(app:"IP.Board", version:vers, install:install, cpe:cpe, concluded: version[0]),
                  port:port);

    }
  }
}
