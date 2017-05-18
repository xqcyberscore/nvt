###############################################################################
# OpenVAS Vulnerability Test
# $Id: novell_imanager_detect.nasl 6040 2017-04-27 09:02:38Z teissa $
#
# Novell iManager Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "Detection of Novell iManager.

This host is running Novell iManager, a Web-based administration
console that provides customized access to network administration
utilities and content from virtually any location.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100434";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 6040 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
 script_tag(name:"creation_date", value:"2010-01-11 11:18:50 +0100 (Mon, 11 Jan 2010)");
 script_tag(name:"qod_type", value:"remote_banner");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Novell iManager Detection");


 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 8080, 8443);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_xref(name : "URL" , value : "http://www.novell.com/products/consoles/imanager/overview.html");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:8080);

if(!get_port_state(port))exit(0);

## Confirm the application
url = string("/nps/servlet/webacc?taskId=dev.Empty&merge=fw.About");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(buf == NULL)exit(0);

if("iManager" >< buf)
{
  ## Port is set again to 8080, as the application set to 8443 after first request.
  port = 8080;
  url = string("/nps/version.jsp"); # http://www.novell.com/coolsolutions/tip/18634.html
  req = http_get(item:url, port:port);

  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  vers = string("unknown");
  ## try to get version
  version = eregmatch(string: buf, pattern: "([0-9.]+)",icase:TRUE);

  if(!isnull(version[1])){
    vers=chomp(version[1]);

    ## Set kb item
    set_kb_item(name: string("www/", port, "/imanager"), value: string(vers));
    set_kb_item(name:"novellimanager/installed",value:TRUE);

    ## Build cpe
    cpe = build_cpe(value:vers, exp:"([0-9.]+)", base:"cpe:/a:novell:imanager:");
    if(isnull(cpe))
      cpe = 'cpe:/a:novell:imanager';

    register_product(cpe:cpe, location:"/", nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"Novell iManager",
                version:vers, install: "/", cpe:cpe, concluded:vers), port:port);
  }
}
