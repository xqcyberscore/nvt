###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cmailserver_detect.nasl 8140 2017-12-15 12:08:32Z cfischer $
#
# CMailServer Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900917");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 8140 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 13:08:32 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("CMailServer Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/smtp", 25, "Services/imap", 143, "Services/pop3", 110);
  script_tag(name : "summary" , value : "The script detects the installed version of CMailServer and sets the result into the knowledgebase." );
  exit(0);
}

include("smtp_func.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("cpe.inc");
include("host_details.inc");

smtpPorts = get_kb_list("Services/smtp");
if(!smtpPorts) smtpPorts = make_list(25);

foreach port(smtpPorts){
  if(get_port_state(port)){
    banner = get_smtp_banner(port: port);

    if((banner != NULL) && ("CMailServer" >< banner)){
      set_kb_item(name: "CMailServer/Installed", value: TRUE);
      ver = eregmatch(pattern: "CMailServer ([0-9.]+)", string: banner);
      version = "unknown";

      if(ver[1]){
        version = ver[1];
        set_kb_item(name: "CMailServer/Ver", value: version);
      }

      cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:youngzsoft:cmailserver:");
      if (!cpe)
        cpe = "cpe:/a:youngzsoft:cmailserver";

      register_product(cpe: cpe, location: "/", port: port, service: "smtp");

      log_message(data: build_detection_report(app: "Youngzsoft CMailServer",
                                               version: version,
                                               install: "/",
                                               cpe: cpe,
                                               concluded: ver[0]),
                                               port: port);
    }
  }
}


imapPorts = get_kb_list("Services/imap");
if(!imapPorts) imapPorts = make_list(143);

foreach port(imapPorts){
  if(get_port_state(port)){
    banner = get_imap_banner(port: port);

    if((banner != NULL) && ("CMailServer" >< banner)){
      set_kb_item(name: "CMailServer/Installed", value: TRUE);
      ver = eregmatch(pattern: "CMailServer ([0-9.]+)", string: banner);
      version = "unknown";

      if(ver[1]){
        version = ver[1];
        set_kb_item(name: "CMailServer/Ver", value: version);
      }

      cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:youngzsoft:cmailserver:");
      if (!cpe)
        cpe = "cpe:/a:youngzsoft:cmailserver";

      register_product(cpe: cpe, location: "/", port: port, service: "imap");

      log_message(data: build_detection_report(app: "Youngzsoft CMailServer",
                                               version: version,
                                               install: "/",
                                               cpe: cpe,
                                               concluded: ver[0]),
                                               port: port);
    }
  }
}


popPorts = get_kb_list("Services/pop3");
if(!popPorts) popPorts = make_list(110);

foreach port(popPorts){
  if(get_port_state(port)){
    banner = get_pop3_banner(port: port);

    if((banner != NULL) && ("CMailServer" >< banner)){
      set_kb_item(name: "CMailServer/Installed", value: TRUE);
      ver = eregmatch(pattern: "CMailServer ([0-9.]+)", string: banner);
      version = "unknown";

      if(ver[1]){
        version = ver[1];
        set_kb_item(name: "CMailServer/Ver", value: version);
      }

      cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:youngzsoft:cmailserver:");
      if (!cpe)
        cpe = "cpe:/a:youngzsoft:cmailserver";

      register_product(cpe: cpe, location: "/", port: port, service: "pop3");

      log_message(data: build_detection_report(app: "Youngzsoft CMailServer",
                                               version: version,
                                               install: "/",
                                               cpe: cpe,
                                               concluded: ver[0]),
                                               port: port);
    }
  }
}

exit(0);
