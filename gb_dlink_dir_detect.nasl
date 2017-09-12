###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir_detect.nasl 7083 2017-09-08 11:53:47Z teissa $
#
# Dlink DIR Devices Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

tag_summary = "Detection of Dlink DIR Devices
                    
The script sends a connection request to the server and attempts to
determine if the remote host is a Dlink DIR device from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103689";   

if (description)
{
 
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 7083 $");
 script_tag(name:"last_modification", value:"$Date: 2017-09-08 13:53:47 +0200 (Fri, 08 Sep 2017) $");
 script_tag(name:"creation_date", value:"2013-04-08 13:52:56 +0200 (Mon, 08 Apr 2013)");
 script_name("Dlink DIR Devices Detection");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80, 8080);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("global_settings.inc");
include("host_details.inc");

port = get_http_port(default:8080);

if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);

fw = FALSE;
typ = FALSE;

if(banner =~ "Server: Linux, ((HTTP/1.1)|(WEBACCESS/1.0)), DIR-[0-9]+[^ ]++ Ver") {

  typ = 'unknown';
  dlink_typ = eregmatch(pattern:", DIR-([^ ]+)", string:banner);
  if(!isnull(dlink_typ[1])) typ = dlink_typ[1];

  fw = 'unknown';
  fw_version = eregmatch(pattern:string("Ver ([^\r\n]+)"), string:banner);
  if(!isnull(fw_version[1])) fw = fw_version[1];
  concluded = banner;

  res = http_get_cache(port: port, item: "/");
  hw_version = eregmatch(pattern: 'Hardware Version : (<span class="value" style="text-transform:uppercase;">)?([^ <]+)<',
                         string: res);
  if (!isnull(hw_version[2]))
    hw = hw_version[2];

}  else {

  if("Server: Mathopd/" >< banner) {
  
    url = "/";
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>D-LINK" >< buf && "LOGIN_USER" >!< buf) {

      url = "/index_temp.php";
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    }  

    if("<title>D-LINK" >!< buf && "LOGIN_USER" >!< buf)exit(0);

    typ = 'unknown';
    dlink_typ = eregmatch(pattern:"class=l_tb>DIR-([^ <]+)<", string:buf);
    if(!isnull(dlink_typ[1])) typ = dlink_typ[1];

    fw = 'unknown';
    fw_version = eregmatch(pattern:string(">Firmware Version&nbsp;:&nbsp;([^& ]+)&nbsp;<"), string:buf);
    if(!isnull(fw_version[1])) fw = fw_version[1];
    concluded = dlink_typ[0] + ' ' + fw_version[0];

    hw_version = eregmatch(pattern: string(">Hardware Version&nbsp;:&nbsp;([^& ]+)&nbsp;<"), string:buf);
    if (!isnull(hw_version[1]))
      hw = hw_version[1];
  }

  else {
    if ("Server: WebServer" >< banner) {
      res = http_get_cache(port: port, item: "/");

      if ("<title>D-LINK" >< res && "WEB FILE ACCESS LOGIN" >< res) {
        fw = 'unknown';
        typ = 'unknown';

        dlink_typ =  eregmatch(pattern: "Product Page : DIR-([^ <]+)<", string: res);
        if (!isnull(dlink_typ[1]))
          typ = dlink_typ[1];

        fw_version = eregmatch(pattern: "Firmware Version : ([0-9.]+)<", string: res);
        if (!isnull(fw_version[1]))
          fw = fw_version[1];

        concluded = dlink_typ[0] + ' ' + fw_version[0];

        hw_version = eregmatch(pattern: "Hardware Version : ([^ <]+)<", string: res);
        if (!isnull(hw_version[1]))
          hw = hw_version[1];
      }
    }
  }
}

if(fw && typ) {

  tmp_cpe = 'cpe:/h:dlink:dir-' + typ;

  cpe = build_cpe(value:tolower(fw), exp:"^([0-9A-Za-z.]+)", base: tmp_cpe + ":");
  if(isnull(cpe))
    cpe = tmp_cpe;

  set_kb_item(name:"host_is_dlink_dir", value:TRUE);
  set_kb_item(name:"dlink_typ", value:'DIR-' + typ);
  set_kb_item(name:"dlink_fw_version", value:fw);
  set_kb_item(name:"dlink_dir_port", value: port);
  if (hw)
    set_kb_item(name: "dlink_hw_version", value: hw);

  register_product(cpe:cpe, location:port + '/tcp', nvt:SCRIPT_OID, port:port);

  log_message(data: build_detection_report(app:"Dlink DIR-" + typ, version:fw, install:port + '/tcp', cpe:cpe, concluded: concluded),
              port:port);

  exit(0);

}  
