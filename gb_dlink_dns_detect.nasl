###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dns_detect.nasl 7853 2017-11-21 15:12:03Z cfischer $
#
# D-Link DNS Devices Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.106015");
 script_version("$Revision: 7853 $");
 script_tag(name: "last_modification", value: "$Date: 2017-11-21 16:12:03 +0100 (Tue, 21 Nov 2017) $");
 script_tag(name: "creation_date", value: "2015-07-10 14:32:27 +0700 (Fri, 10 Jul 2015)");
 script_tag(name: "cvss_base", value: "0.0");
 script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

 script_tag(name: "qod_type", value: "remote_banner");

 script_name("D-Link DNS Devices Detection");

 script_tag(name: "summary" , value: "Detection of D-Link DNS Devices

The script sends a connection request to the server and attempts to detect D-Link DNS Devices.");

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_family("Product detection");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("D-LinkDNS/banner");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);

# DNS-320, DNS-320L, DNS-325, DNS-327L, DNS-345
if ("Server: lighttpd/" >< banner) {
  res = http_get_cache(item: "/", port: port);

  if ("Please Select Your Account" >< res && "ShareCenter" >< res) {
    typ = 'unknown';
    fw = 'unknown';

    url = "/xml/info.xml";
    req = http_get(item: url, port: port);
    res = http_keepalive_send_recv(port: port, data: req);
   
    if (res =~ "<info>" && res =~ "www.dlink.com") {
      dlink_typ = eregmatch(pattern: "<hw_ver>(.*)</hw_ver>", string: res);
      if (!isnull(dlink_typ[1]))
        typ = dlink_typ[1];
      
      fw_version = eregmatch(pattern: "<version>(.*)</version>", string: res);
      if (!isnull(fw_version[1]))
        fw = fw_version[1];
    }
  }
}
# DNS-321, DNS-323, DNS-343
else if ("Server: GoAhead-Webs" >< banner) {
  req = http_get(item: "/web/login.asp", port: port);
  res = http_keepalive_send_recv(port: port, data: req);

  if (egrep(string: res, pattern: "<TITLE>dlink(.*)?</TITLE>", icase: TRUE) &&
      "D-Link Corporation/D-Link Systems, Inc." >< res) {
    typ = 'unknown';
    fw = 'unknown';
  }
}

if (fw && typ) {
  set_kb_item(name: "host_is_dlink_dns", value: TRUE);
  set_kb_item(name: "dlink_typ", value: typ);
  set_kb_item(name: "dlink_fw_version", value: fw);
  set_kb_item(name: "dlink_dns_port", value: port);

  if (typ != 'unknown')
    tmp_cpe = 'cpe:/h:d-link:' + tolower(typ);
  else
    tmp_cpe = 'cpe:/h:d-link:dns-' + typ;
  
  cpe = build_cpe(value: fw, exp: "^([0-9.]+)", base: tmp_cpe + ":");
  if (isnull(cpe))
    cpe = tmp_cpe;

  register_product(cpe: cpe, port: port);

  log_message(data: build_detection_report(app: "D-Link DNS " + typ, version: fw, install: port + '/tcp',
                                           cpe: cpe),
              port: port);

}
