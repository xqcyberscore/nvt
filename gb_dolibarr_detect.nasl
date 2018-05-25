###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolibarr_detect.nasl 9949 2018-05-24 12:33:20Z jschulte $
#
# Dolibarr Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103143");
  script_version("$Revision: 9949 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-05-24 14:33:20 +0200 (Thu, 24 May 2018) $");
  script_tag(name:"creation_date", value:"2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Dolibarr Detection");

  script_tag(name:"summary", value:"Detection of installed version of
  Dolibarr, an opensource ERP/CRM Software.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name : "URL" , value : "http://www.dolibarr.org/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

dolport = get_http_port(default:80);
if(!can_host_php(port:dolport)) exit(0);
foreach dir( make_list_unique("/", "/dolibarr","/dolibarr/htdocs","/htdocs",cgi_dirs(port:dolport)) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = string(dir, "/index.php");
  buf = http_get_cache(item:url, port:dolport);
  if( buf == NULL )continue;

  if("Set-Cookie: DOLSESSID" >< buf && ("<title>Login" || "<title>Dolibarr") >< buf
      && ("dolibarr_logo.png" || "dolibarr.org") >< buf)
  {
    vers = string("unknown");
    version = eregmatch(string: buf, pattern: ">Dolibarr.{0,5} ([0-9.]+)<",icase:TRUE);
    if (!isnull(version[1])){
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", dolport, "/dolibarr"), value: string(vers," under ",install));
    set_kb_item(name: "Dolibarr/installed", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:dolibarr:dolibarr:");
    if(!cpe)
      cpe = "cpe:/a:dolibarr:dolibarr";

    register_product(cpe:cpe, location:install, port:dolport);

    log_message(data:build_detection_report( app:"Dolibarr ERP/CRM",
                                             version:vers,
                                             install:install,
                                             cpe:cpe,
                                             concluded:vers),
                                             port:dolport);
    exit(0);
 }
}
exit(0);

