###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_banner_grabber.nasl 8233 2017-12-22 09:37:31Z cfischer $
#
# Wrapper for Nmap Banner Grabber NSE script.
#
# Authors:
# NSE-Script: jah <jah at zadkiel.plus.com>
# NASL-Wrapper: Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
# NASL-Wrapper: Copyright (c) 2010 Greenbone Networks GmbH (http://www.greenbone.net)
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

tag_summary = "This script attempts to connect to the target port and returns
  the banner of the remote service.

  This is a wrapper on the Nmap Security Scanner's (http://nmap.org) banner.nse";


if(description)
{
  script_id(801253);
  script_version("$Revision: 8233 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 10:37:31 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-08-10 12:08:05 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Nmap NSE: Banner Grabber");
  script_category(ACT_GATHER_INFO);
  script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE");
  script_dependencies("toolcheck.nasl", "secpod_open_tcp_ports.nasl");
  script_mandatory_keys("Tools/Present/nmap", "Tools/Launch/nmap_nse", "TCP/PORTS");
  script_tag(name : "summary" , value : tag_summary);

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");

if((! get_kb_item("Tools/Present/nmap5.21") &&
   ! get_kb_item("Tools/Present/nmap5.51")) ||
   ! get_kb_item("Tools/Launch/nmap_nse")) {
 exit(0);
}

port = get_all_tcp_ports();

res = pread(cmd: "nmap", argv: make_list("nmap", "--script=banner", "-p", port, get_host_ip()));
if(res)
{
  foreach line (split(res))
  {
    ## Get Banner
    if(ereg(pattern:"^\|",string:line)) {
      result +=  substr(chomp(line),2);
    }

    error = eregmatch(string:line, pattern:"^nmap: (.*)$");
    if (error) {
      msg = string('Nmap command failed with following error message:\n', line);
      log_message(data : msg, port:port);
    }
  }

  if("banner" >< result) {
    msg = string('Result found by Nmap Security Scanner (banner.nse) ',
                'http://nmap.org:\n\n', result);
    security_message(data : msg, port:port);
  }
}
else
{
  msg = string('Nmap command failed entirely:\n');
  log_message(data : msg, port:port);
}
