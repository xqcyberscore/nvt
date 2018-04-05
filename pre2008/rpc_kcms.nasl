###############################################################################
# OpenVAS Vulnerability Test
# $Id: rpc_kcms.nasl 9328 2018-04-05 11:14:07Z cfischer $
#
# Kcms Profile Server
#
# Authors:
# Michael Scheidell  <scheidell at secnap.net>
# based on a script written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2002 Michael Scheidell
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10832");
  script_version("$Revision: 9328 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 13:14:07 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2605);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0595");
  script_name("Kcms Profile Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michael Scheidell");
  script_family("RPC");
  script_dependencies("secpod_rpc_portmap.nasl", "os_detection.nasl");
  script_require_keys("rpc/portmap");

  script_xref(name:"URL", value:"http://packetstorm.decepticons.org/advisories/ibm-ers/96-09");
  script_xref(name:"URL", value:"http://www.eeye.com/html/Research/Advisories/AD20010409.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2605");

  script_tag(name:"solution", value:"Disable suid, side effects are minimal.");

  script_tag(name:"summary", value:"The Kodak Color Management System service is running.

  The KCMS service on Solaris 2.5 could allow a local user
  to write to arbitrary files and gain root access.

  *** This warning may be a false
  *** positive since the presence
  *** of the bug has not been tested.

  Patches: 107337-02 SunOS 5.7 has been released
  and the following should be out soon:
  111400-01 SunOS 5.8, 111401-01 SunOS 5.8_x86");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("byte_func.inc");

version = get_kb_item( "ssh/login/solosversion" );
if( version && ereg( pattern:"5\.1[0-9]", string:version ) ) exit(0);

RPC_PROG = 100221;
tcp = FALSE;
port = get_rpc_port( program:RPC_PROG, protocol:IPPROTO_UDP );
if( ! port ) {
  port = get_rpc_port( program:RPC_PROG, protocol:IPPROTO_TCP );
  tcp = TRUE;
}

if( port ) {
  if( host_runs( "Solaris (2\.[56]|[7-9])") != "no" ) {
    if( tcp ) {
      security_message( port:port );
    } else {
      security_message( port:port, protocol:"udp" );
    }
    exit( 0 );
  }
}

exit( 99 );