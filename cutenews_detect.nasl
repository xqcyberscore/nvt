###############################################################################
# OpenVAS Vulnerability Test
# $Id: cutenews_detect.nasl 2837 2016-03-11 09:19:51Z benallard $
#
# CuteNews Detection
#
# Authors:
# Michael Meyer
#
# Updated to detect UTF-8 CuteNews
#  - By Antu Sanadi <santu@secpod.com> On 2009-12-05 #5990
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

tag_summary = "This host is running CuteNews, a powerful and easy to use news
  management system that uses flat files to store its database";

if (description)
{
 script_id(100105);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2837 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
 script_tag(name:"creation_date", value:"2009-04-05 20:39:41 +0200 (Sun, 05 Apr 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("CuteNews Detection");
 script_summary("Checks for the presence of CuteNews");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("General");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://cutephp.com/cutenews/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100105";
SCRIPT_DESC = "CuteNews Detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/cutenews","/utf-8", "/news", "/", cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/index.php");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( buf == NULL )continue;
  if(egrep(pattern: "Powered by <a [^>]+>CuteNews", string: buf, icase: TRUE) ||
    egrep(pattern: "Powered by <a [^>]+>UTF-8 CuteNews", string: buf, icase: TRUE))
  {

    if(strlen(dir)>0) {
      install=dir;
     }
     else {
        install=string("/");
     }

     vers = string("unknown");

     ### try to get version
     if(version = eregmatch(string: buf, pattern: "Powered by <a [^>]+>CuteNews v*([0-9.]+)</a>",icase:TRUE))
     {
       if ( !isnull(version[1])) {
         vers=version[1];
       }

       tmp_version = string(vers," under ",install);
       set_kb_item(name: string("www/", port, "/cutenews"), value: tmp_version);
    
       ## build cpe and store it as host detail
       register_cpe(tmpVers:tmp_version,tmpExpr:"^([0-9.]+)",tmpBase:"cpe:/a:cutephp:cutenews:");

     }

     else if("<title>UTF-8 CuteNews</title>" >< buf)
     {
       version = eregmatch(string: buf, pattern: "UTF-8 CuteNews (([0-9.]+)([a-z]+)?)", icase:TRUE);
       if(!isnull(version[1])) {
         vers=version[1];
       }

       tmp_version = string(vers," under ",install);
       set_kb_item(name: string("www/", port, "/UTF-8/cutenews"), value: tmp_version);

       ## build cpe and store it as host detail
       register_cpe(tmpVers:tmp_version,tmpExpr:"^([0-9.]+)",tmpBase:"cpe:/a:cutephp:cutenews:");

     }

     desc = string("CuteNews Version '");
     desc += string(vers);
     desc += string("' was detected on the remote host in the following directory(s):\n\n");
     desc += string(install, "\n");

     if(report_verbosity > 0) {
         log_message(port:port,data:desc);
     }
   }
}
