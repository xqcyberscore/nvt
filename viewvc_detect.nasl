###############################################################################
# OpenVAS Vulnerability Test
# $Id: viewvc_detect.nasl 8087 2017-12-12 13:12:04Z teissa $
#
# ViewVC Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "This host is running ViewVC, a browser interface for CVS and
Subversion version control repositories.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100261");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8087 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-12 14:12:04 +0100 (Tue, 12 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-08-26 20:38:31 +0200 (Wed, 26 Aug 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("ViewVC Detection");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.viewvc.org/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100261";
SCRIPT_DESC = "ViewVC Detection";

port = get_http_port(default:80);

vcs = make_list("/viewvc","/viewvc.cgi");

foreach dir( make_list_unique( "/svn", "/scm", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";

 foreach vc( vcs ) {

  url = string(dir,vc,"/");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( buf == NULL )continue;

  if(egrep(pattern: "Powered by <a[^>]+>ViewVC", string: buf, icase: TRUE) ||
     egrep(pattern: "<meta.*generator.*ViewVC", string: buf, icase: TRUE) )
  {
     vers = string("unknown");
     ### try to get version 
     version = eregmatch(string: buf, pattern: "ViewVC ([0-9.]+[-dev]*)",icase:TRUE);

     if ( !isnull(version[1]) ) {
        vers=chomp(version[1]);
     }

     tmp_version = string(vers," under ",install);
     set_kb_item(name: string("www/", port, "/viewvc"), value: tmp_version);
   
     ## build cpe and store it as host_detail
     cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+-?([a-z0-9]+)?)", base:"cpe:/a:viewvc:viewvc:");
     if(!isnull(cpe))
        register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
 
     info = string("ViewVC Version '");
     info += string(vers);
     info += string("' was detected on the remote host in the following directory(s):\n\n");
     info += string(install, "\n");
     
     log_message(port:port,data:info);
     exit(0);
   }
 }
}

exit(0);
