###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_realvnc_auth_bypass.nasl 10580 2018-07-23 13:56:07Z cfischer $
#
# Wrapper for Nmap RealVNC Authentication Bypass NSE script.
#
# Authors:
# NSE-Script: Brandon Enright <bmenrigh@ucsd.edu>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801697");
  script_version("$Revision: 10580 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-23 15:56:07 +0200 (Mon, 23 Jul 2018) $");
  script_tag(name:"creation_date", value:"2011-01-10 13:49:23 +0100 (Mon, 10 Jan 2011)");
  script_cve_id("CVE-2006-2369");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Nmap NSE: RealVNC Authentication Bypass");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE");
  script_dependencies("vnc.nasl", "nmap_nse.nasl");
  script_require_ports("Services/vnc", 5900);
  script_mandatory_keys("Tools/Present/nmap", "Tools/Launch/nmap_nse");

  script_tag(name:"summary", value:"This script attempts to check if a VNC server is vulnerable to
  the RealVNC authentication bypass (CVE-2006-2369).

  This is a wrapper on the Nmap Security Scanner's (http://nmap.org) realvnc-auth-bypass.nse.");

  exit(0);
}

if((! get_kb_item("Tools/Present/nmap5.21") &&
   ! get_kb_item("Tools/Present/nmap5.51")) ||
   ! get_kb_item("Tools/Launch/nmap_nse")) {
 exit(0);
}

port = get_kb_item("Services/vnc");
if(!port) {
  port = 5900;
}

if(!get_port_state(port)){
  exit(0);
}

res = pread(cmd: "nmap", argv: make_list("nmap", "--script=realvnc-auth-bypass.nse", "-p", port, get_host_ip()));
if(res)
{
  foreach line (split(res))
  {
    if(ereg(pattern:"^\|",string:line)) {
      result +=  substr(chomp(line),2) + '\n';
    }

    error = eregmatch(string:line, pattern:"^nmap: (.*)$");
    if (error) {
      msg = string('Nmap command failed with following error message:\n', line);
      log_message(data : msg, port:port);
    }
  }

  if("realvnc-auth-bypass" >< result) {
    msg = string('Result found by Nmap Security Scanner (realvnc-auth-bypass.nse) ',
                'http://nmap.org:\n\n', result);
    security_message(data : msg, port:port);
  }
}
else
{
  msg = string('Nmap command failed entirely:\n');
  log_message(data : msg, port:port);
}
