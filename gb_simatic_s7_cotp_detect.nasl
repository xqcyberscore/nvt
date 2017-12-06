###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_s7_cotp_detect.nasl 7998 2017-12-06 04:32:22Z ckuersteiner $
#
# Siemens SIMATIC S7 Device Detection (COTP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
 script_oid("1.3.6.1.4.1.25623.1.0.106099");
 script_version ("$Revision: 7998 $");
 script_tag(name: "last_modification", value: "$Date: 2017-12-06 05:32:22 +0100 (Wed, 06 Dec 2017) $");
 script_tag(name: "creation_date", value: "2016-06-17 17:08:52 +0700 (Fri, 17 Jun 2016)");
 script_tag(name: "cvss_base", value: "0.0");
 script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

 script_tag(name: "qod_type", value: "remote_banner");

 script_name("Siemens SIMATIC S7 Device Detection (COTP)");

 script_tag(name: "summary" , value: "This script performs COTP (Connection-Oriented Transport Protocol)
based detection of Siemens SIMATIC S7 devices.");

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_family("Product detection");
 script_dependencies("find_service.nasl");
 script_require_ports(102);


 exit(0);
}

include("http_func.inc");     # for hex2dec
include("byte_func.inc");

function cotp_send_recv( req, soc )
{
  local_var req, soc;
 
  send(socket: soc, data:req);
  recv = recv(socket: soc, length: 6, min: 6);
 
  if (strlen(recv) < 6)
    return;
 
  len = (getword(blob: recv, pos: 2) - 6);
 
  if (len < 1 || len > 65535)
    return;
 
  recv += recv(socket: soc, length: len);
 
  if (strlen( recv ) != (len + 6))
    return;
 
  return recv;
}

function cotp_extract_packet( data ) {
  local_var data;

  cotpPacket = substr(data, 7);
  if (hexstr(cotpPacket[1]) == "01" || hexstr(cotpPacket[1]) == "07")
    header_length = 10;
  else
    header_length = 12;

  param_length = getword(blob: cotpPacket, pos: 6);
  return substr(cotpPacket, header_length + param_length);
}


port = 102;

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc) 
  exit();

# COTP connection request
connectionReq = raw_string(0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00,
                           0x00, 0x02, 0x00, 0xc1, 0x02, 0x01, 0x00, 0xc2,
                           0x02, 0x01, 0x02, 0xc0, 0x01, 0x0a);

recv = cotp_send_recv(req: connectionReq, soc: soc);

if (!recv || hexstr(recv[5]) != "d0") {
  # we have to open a new socket
  close(soc);

  soc = open_sock_tcp(port);
  if (!soc) 
    exit();

  # Try an alternative request
  connectionReq = raw_string(0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00,
                             0x00, 0x05, 0x00, 0xc1, 0x02, 0x01, 0x00, 0xc2,
                             0x02, 0x02, 0x00, 0xc0, 0x01, 0x0a);
  recv = cotp_send_recv(req: connectionReq, soc: soc);

  if (!recv || hexstr(recv[5]) != "d0") {
    close(soc);
    exit(0);
  }
}

negotiatePdu = raw_string(0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80, 0x32,
                          0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
                          0x00, 0xf0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01,
                          0xe0);

recv = cotp_send_recv(req: negotiatePdu, soc: soc);

if (!recv)
  exit(0);

readModuleID = raw_string(0x03, 0x00, 0x00, 0x21, 0x02, 0xf0, 0x80, 0x32,
                          0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
                          0x08, 0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01,
                          0x00, 0xff, 0x09, 0x00, 0x04, 0x00, 0x11, 0x00,
                          0x01);

recv = cotp_send_recv(req: readModuleID, soc: soc);

if (!recv)
  exit(0);

dataPacket = cotp_extract_packet(data: recv);

if (hexstr(dataPacket[0]) != "ff")
  exit(0);

version = "unknown";

if (strlen(dataPacket) >= 96) {
  ver = hexstr(substr(dataPacket, 93, 95));

  v1 = ver[0] + ver[1];
  v2 = ver[2] + ver[3];
  v3 = ver[4] + ver[5];
  version = hex2dec(xvalue: v1) + '.' + hex2dec(xvalue: v2) + '.' + hex2dec(xvalue: v3);
}

# Read the component identifications to extract the model
readComponentID = raw_string(0x03, 0x00, 0x00, 0x21, 0x02, 0xf0, 0x80, 0x32,
                             0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
                             0x08, 0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01,
                             0x00, 0xff, 0x09, 0x00, 0x04, 0x00, 0x1c, 0x00,
                             0x01);

recv = cotp_send_recv(req: readComponentID, soc: soc);
model = "unknown";

if (recv) {
  dataPacket = cotp_extract_packet(data: recv);

  if (hexstr(dataPacket[0]) == "ff") {
    dataPacket = substr(dataPacket, 4);

    element_size = getword(blob: dataPacket, pos: 4);
    dataPacket = substr(dataPacket, 8);

    for (i=0; i<strlen(dataPacket); i=i+element_size) {
      element = substr(dataPacket, i, i+element_size);
      if (hexstr(element[1]) == "01") {
        plcName = substr(element, 2);
        mod = eregmatch(pattern: "simatic([ ,]+)?(.*)", string: plcName, icase: TRUE);
        if (mod[2]) {
          model = mod[2];
        }
      }
      else
        if (hexstr(element[1]) == "02") {
          moduleName = substr(element, 2);
          mod = eregmatch(pattern: "((CPU )||(S7-))(.*)", string: moduleName, icase: TRUE);
          if (mod[4]) {
            model = mod[4];
          }
       }
       else if (hexstr(element[1]) == "07") {
         moduleType = substr(element, 2);
         # We get this just over COTP, therefore set the KB direct
         set_kb_item(name: "simatic_s7/modtype", value: moduleType);
       }
    }
  }
}

if (model != "unknown" || version != "unknown") {
  set_kb_item(name: "simatic_s7/detected", value: TRUE);
  if (model != "unknown") {
    if (egrep(string: model, pattern: "^3.."))
      model = 300;
    set_kb_item(name: "simatic_s7/cotp/model", value: model);
  }

  if (version != "unknown")
    set_kb_item(name: "simatic_s7/cotp/version", value: version);

  set_kb_item(name: "simatic_s7/cotp/port", value: port);
}

close(soc);

exit(0);
