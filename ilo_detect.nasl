# OpenVAS Vulnerability Test
# $Id: ilo_detect.nasl 8078 2017-12-11 14:28:55Z cfischer $
# Description: HP Integrated Lights-Out Detection
#
# Authors:
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Modifications by Tenable :
# - Description
# Modifications by Daniel Reich <me at danielreich dot com>
# - Added detection for HP Remote Insight ILO Edition II
# - Removed &copy; in original string, some versions flip the 
#   order of Copyright and &copy;
#
# Copyright:
# Copyright (C) 2005 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.20285");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8078 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-11 15:28:55 +0100 (Mon, 11 Dec 2017) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("HP Integrated Lights-Out Detection");

 tag_summary =
"The script sends a connection request to the server and attempts to
extract the version number from the reply.";

 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"remote_banner");

 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 script_family("Product detection");
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);

}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:443);

r = http_get_cache(item:"/", port:port);
if( r == NULL )exit(0);

if((r =~ "(<title>HP iLO Login</title>|<title>iLO [0-9]+</title>)" && "Hewlett-Packard Development Company" >< r) ||
   ("HP Integrated Lights-Out" >< r && egrep(pattern:"Copyright .+ Hewlett-Packard Development Company", string:r)) ||
   ("<title>HP Remote Insight<" >< r &&  egrep(pattern:"Hewlett-Packard Development Company", string:r) ) ||
   "Server: HP-iLO-Server" >< r) {

  vers = 'unknown';
  ilo_vers = 'unknown';
  concluded = 'Remote probe';
  sso = 0;

  url = '/xmldata?item=All';
  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:TRUE);

  if("Integrated Lights-Out" >< buf) {
    fw_version = eregmatch(pattern:"<FWRI>([^<]+)</FWRI>", string:buf);
    if(!isnull(fw_version[1]))vers = fw_version[1];

    if("<PN>Integrated Lights-Out (iLO)</PN>" >< buf) {
      ilo_vers = 1;
    } else {
     ilo_version = eregmatch(pattern:"<PN>Integrated Lights-Out ([0-9]+) [^<]+</PN>", string:buf);
     if(!isnull(ilo_version[1]))ilo_vers = int(ilo_version[1]);
    }

    _sso = eregmatch(pattern:"<SSO>(0|1)</SSO>", string:buf);
    if(!isnull(_sso[1]))sso = int(_sso[1]);

  }  

  if((vers == 'unknown' || ilo_vers == 'unknown') && r =~ "<title>iLO [0-9]+</title>") {
    url = "/json/login_session";
    req = http_get(item:url, port:port);
    buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
    if('{"secjmp' >< buf) {
      fw_version = eregmatch(pattern:'version":"([^"]+)"', string:buf);
      if(!isnull(fw_version[1]))vers = fw_version[1];

      ilo_version = eregmatch(pattern:"<title>iLO ([0-9]+)</title>", string:r);
      if(!isnull(ilo_version[1]))ilo_vers = int(ilo_version[1]);
    }  

  }  

  if(vers != 'unknown') concluded = fw_version[0];

  set_kb_item(name: string("www/", port, "/HP_ILO"), value: TRUE);
  set_kb_item(name: string("www/", port, "/HP_ILO/fw_version"), value: vers);
  set_kb_item(name: string("www/", port, "/HP_ILO/ilo_version"), value: ilo_vers);
  set_kb_item(name: string("www/", port, "/HP_ILO/sso"), value: sso);
  set_kb_item(name:"HP_ILO/installed",value:TRUE);

  cpe = 'cpe:/o:hp:integrated_lights-out';

  if(vers != 'unknown')
    cpe += ':' + vers;

  register_product(cpe:cpe, location:'/', port:port);
  log_message(data: build_detection_report(app:"HP Integrated Lights-Out " + ilo_vers, version:vers, install:'/', cpe:cpe, concluded:concluded),
              port:port);

  exit(0);

}  
  
exit(0);
