###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_xenserver_vswitch_controller_52641.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Citrix XenServer vSwitch Controller Component Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "Citrix XenServer is prone to multiple unspecified vulnerabilities.

The impact of these issues is currently unknown. We will update this
BID when more information emerges.

Citrix XenServer versions 5.6, 5.6 FP 1, 5.6 SP 2, and 6 are
vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103474");
 script_bugtraq_id(52641);
 script_version ("$Revision: 9352 $");
 script_name("Citrix XenServer vSwitch Controller Component Multiple Vulnerabilities");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52641");
 script_xref(name : "URL" , value : "http://www.citrix.com/English/ps2/products/feature.asp?contentID=1686939");
 script_xref(name : "URL" , value : "http://support.citrix.com/article/CTX132476");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-04-23 11:36:51 +0200 (Mon, 23 Apr 2012)");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
   
port = get_http_port(default:443);

transport = get_port_transport(port);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  soc = open_sock_tcp(port, transport:transport);
  if(!soc)exit(0);

  if( dir == "/" ) dir = "";
  url = dir + '/login';
  req = http_get(item:url, port:port);

  send(socket:soc, data: req);
  buf = recv(socket:soc, length: 1024);

  close(soc);

  if("DVSC_MGMT_UI_SESSION" >!< buf && buf !~ "<title>.*DVS.*Controller") {
    continue;
  }  

  soc = open_sock_tcp(port, transport:transport);
  if(!soc)exit(0);

  url = dir + '/static/';
  req = http_get(item:url, port:port);

  send(socket:soc, data: req);
  buf = recv(socket:soc,length:2048);
  close(soc);

  if("Directory listing for /static" >!< buf) {
    continue;
  } 

  lines = split(buf);
  locs = make_list();

  foreach line (lines) {

    if(locs = eregmatch(pattern:'<a href="([0-9]+)/">', string:line)) {

      loc[i++] = locs[1];

    }  

  }  

  foreach l (loc) {

    soc = open_sock_tcp(port, transport:transport);
    if(!soc)exit(0);

    url = '/static/' + l + '/nox/ext/apps/vmanui/main.js';
    req = http_get(item:url, port:port);
    send(socket:soc, data: req);

    while(buf = recv(socket:soc,length:1024)) {
      recv += buf;
    }  

    close(soc);

    if('dojo.provide("nox.ext.apps.vmanui.main")' >< recv) {

      if("X-CSRF-Token" >!< recv && "oCsrfToken" >!< recv) {
        security_message(port:port);
        exit(0);
      }  

    }  
    
  }  

}  


exit(0);

