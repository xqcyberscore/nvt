###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lxcenter_kloxo_detect.nasl 9996 2018-05-29 07:18:44Z cfischer $
#
# LxCenter Kloxo Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.103977");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 9996 $");
  script_name("LxCenter Kloxo Detection");
  script_xref(name:"URL", value:"http://lxcenter.org/software/kloxo");
  script_tag(name:"last_modification", value:"$Date: 2018-05-29 09:18:44 +0200 (Tue, 29 May 2018) $");
  script_tag(name:"creation_date", value:"2014-02-22 22:54:04 +0700 (Sat, 22 Feb 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 7778);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "summary" , value : "This host is running LxCenter Kloxo. Kloxo is a fully scriptable
hosting platform.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:7778);

url = string("/login/");
buf = http_get_cache(item:url, port:port);
if (buf == NULL) {
  exit(0);
}

if (egrep(pattern:'Kloxo', string:buf, icase:TRUE)) {
  vers = string("unknown");
  version = eregmatch(string:buf, pattern:">Kloxo.* ([0-9.]+[a-z]-[0-9]+)<", icase:TRUE);

  if (!isnull(version[1])) {
    vers =  chomp(version[1]);
  }

  set_kb_item(name:"Kloxo/installed", value:TRUE);
  set_kb_item(name:string("www/", port, "/kloxo"), value:string(vers));
  log_message(data:'Kloxo was detected on the remote host.\nVersion: ' + vers, port:port);
}
