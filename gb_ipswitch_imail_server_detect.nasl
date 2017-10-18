###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipswitch_imail_server_detect.nasl 7461 2017-10-17 13:08:44Z asteins $
#
# Ipswitch IMail Server Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811256");
  script_version("$Revision: 7461 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-17 15:08:44 +0200 (Tue, 17 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-07-26 16:06:50 +0530 (Wed, 26 Jul 2017)");
  script_name("Ipswitch IMail Server Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of Ipswitch IMail Server.

  This script check the presence of Ipswitch IMail Server from the
  banner and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/smtp","Services/pop3","Services/imap","Services/www", 25, 110, 143, 80);
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("smtp_func.inc");
include("pop3_func.inc");
include("imap_func.inc");

function get_version(banner, port)
{
  set_kb_item(name:"Ipswitch/IMail/Installed", value:TRUE);

  mailVer = eregmatch(pattern:"Server: Ipswitch-IMail/([0-9.]+)", string: banner);
  if(!mailVer){
    mailVer = eregmatch(pattern:"IMail ([0-9.]+)", string: banner);
  }

  if(mailVer[1])
  {
    set_kb_item(name: "Ipswitch/IMail/version", value: mailVer[1]);

    cpe = build_cpe(value: mailVer[1], exp: "^([0-9.]+)", base: "cpe:/a:ipswitch:imail_server:");
    if (!cpe)
      cpe = "cpe:/a:ipswitch:imail_server";

    register_product(cpe:cpe, location:"/", port:port);

    log_message(data: build_detection_report(app: "Ipswitch IMail Server",
                                            version: mailVer[1],
                                            install: "/",
                                            cpe: cpe,
                                            concluded: mailVer[0]),
                                            port: port);
    exit(0);
  }
}

mailPorts = get_kb_list("Services/www");
if(!mailPorts) mailPorts = make_list(80) ;

foreach mailPort(mailPorts){
  if(get_port_state(mailPort)) {
    if(banner = get_http_banner(port:mailPort)) {
      if("Server: Ipswitch-IMail" >< banner) {
        get_version(banner:banner, port:mailPort);
      }
    }
  }
}

mailPorts = get_kb_list("Services/pop3");
if(!mailPorts) mailPorts = make_list(110) ;

foreach mailPort(mailPorts){
  if(get_port_state(mailPort)) {
    if(banner = get_pop3_banner(port:mailPort)) {
      if("IMail" >< banner) {
        get_version(banner:banner, port:mailPort);
      }
    }
  }
}

mailPorts = get_kb_list("Services/smtp");
if(!mailPorts) mailPorts = make_list(25) ;

foreach mailPort(mailPorts){
  if(get_port_state(mailPort)) {
    if(banner = get_smtp_banner(port:mailPort)) {
      if("IMail" >< banner) {
        get_version(banner:banner, port:mailPort);
      }
    }
  }
}

mailPort = get_kb_list("Services/imap");
if(!mailPorts) mailPorts = make_list(143);

foreach mailPort(mailPorts){
  if(get_port_state(mailPort)) {
    if(banner = get_imap_banner(port:mailPort)) {
      if("IMail" >< banner) {
        get_version(banner:banner,port:mailPort);
      }
    }
  }
}

exit(0);
