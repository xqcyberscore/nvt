###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lxcenter_kloxo_detect.nasl 2836 2016-03-11 09:07:07Z benallard $
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103977";
SCRIPT_DESC = "LxCenter Kloxo Detection";

tag_summary = "This host is running LxCenter Kloxo. Kloxo is a fully scriptable
hosting plattform.";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 2836 $");

  script_name(SCRIPT_DESC);


  script_xref(name:"URL", value:"http://lxcenter.org/software/kloxo");
  script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:07:07 +0100 (Fri, 11 Mar 2016) $");
  script_tag(name:"creation_date", value:"2014-02-22 22:54:04 +0700 (Sat, 22 Feb 2014)");

  script_summary("Checks for the presence of LxCenter Kloxo");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 7778);

  script_tag(name : "summary" , value : tag_summary);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:7778);
if (!get_port_state(port)) {
  exit(0);
}

url = string("/login/");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if (buf == NULL) {
  exit(0);
}

if (egrep(pattern:'Kloxo', string:buf, icase:TRUE)) {
  vers = string("unknown");
  # try to get version
  version = eregmatch(string:buf, pattern:">Kloxo.* ([0-9.]+[a-z]-[0-9]+)<", icase:TRUE);

  if (!isnull(version[1])) {
    vers =  chomp(version[1]);
  }

  set_kb_item(name:"Kloxo/installed", value:TRUE);
  set_kb_item(name:string("www/", port, "/kloxo"), value:string(vers));
  log_message(data:'Kloxo was detected on the remote host.\nVersion: ' + vers, port:port);
}
