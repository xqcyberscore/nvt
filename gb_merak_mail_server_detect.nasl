###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_merak_mail_server_detect.nasl 9584 2018-04-24 10:34:07Z jschulte $
#
# Merak Mail Server Web Mail Version Detection
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2011-09-27
#   Updated to detect the recent versions.
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "Detection of Merak Mail Server Web Mail.
                     
The script sends a connection request to the server and attempts to
extract the version number from the reply.

This NVT has been replaced by gb_icewarp_web_detect.nasl (1.3.6.1.4.1.25623.1.0.140329) and
gb_icewarp_mail_detect.nasl (1.3.6.1.4.1.25623.1.0.140330).";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800096";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 9584 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-24 12:34:07 +0200 (Tue, 24 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-02 09:27:25 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Merak Mail Server Web Mail Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IceWarp/banner");
  script_require_ports("Services/www", 80, 32000);
  script_tag(name : "summary" , value : tag_summary);

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("IceWarp" >!< banner){
  exit(0);
}

version = eregmatch(pattern:"(Merak|IceWarp).?([0-9.]+)", string:banner);
if(version[2] == NULL)
{
  smtpPort = get_kb_item("Services/smtp");
  if(!smtpPort){
    smtpPort = 25;
  }

  imapPort = get_kb_item("Services/imap");
  if(!imapPort){
    imapPort = 143;
  }

  popPort = get_kb_item("Services/pop3");
  if(!popPort){
    popPort = 110;
  }

  foreach port (make_list(smtpPort, imapPort, popPort))
  {
    banner = get_kb_item(string("Banner/", port));
    if(banner =~ "IceWarp|Merak")
    {
      version = eregmatch(pattern:"(Merak|IceWarp) ([0-9.]+)", string:banner);
      if(version[2] != NULL){
         ver = version[2];
     }
   }
  }
}
else if(version[2] != NULL){
 ver = version[2];
}

if(ver) {

  foreach dir( make_list_unique( "/webmail", cgi_dirs( port:port ) ) ) {
    install = dir;
    if( dir == "/" ) dir = "";
    url = dir + '/';
    buf = http_get_cache(item:url, port:port);
    if(buf =~ "<title>(Merak|IceWarp)") {
      break;
    }
  }

  set_kb_item(name:"MerakMailServer/Ver", value:ver);
  cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:icewarp:merak_mail_server:");
  if(isnull(cpe))
    cpe = 'cpe:/a:icewarp:merak_mail_server';

   register_product(cpe:cpe, location:install, port:port);

   log_message(data: build_detection_report(app:"Merak Mail Server Web Mail", version:ver, install:install, cpe:cpe, concluded: banner),
               port:port);
   exit(0);
  
}

exit(0);
