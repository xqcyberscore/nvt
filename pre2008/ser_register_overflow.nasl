###############################################################################
# OpenVAS Vulnerability Test
# $Id: ser_register_overflow.nasl 4881 2016-12-29 20:40:48Z cfi $
#
# SIP Express Router Register Buffer Overflow
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
  script_oid("1.3.6.1.4.1.25623.1.0.11965");
  script_version("$Revision: 4881 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-29 21:40:48 +0100 (Thu, 29 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("SIP Express Router Register Buffer Overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("Buffer overflow");
  script_dependencies("sip_detection.nasl", "find_service.nasl");
  script_mandatory_keys("sip/detected");

  script_tag(name:"solution", value:"Upgrade to version 0.8.11 or use the patch provided at:
  http://www.iptel.org/ser/security/secalert-002-0_8_10.patch

  For additional details see: http://www.iptel.org/ser/security/");

  script_tag(name:"summary", value:"The remote host is running a SIP Express Router.

  A bug has been found in the remote device which may allow an attacker to
  crash this device by sending a too long contact list in REGISTERs.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("sip.inc");

infos = get_sip_port_proto( default_port:"5060", default_proto:"udp" );
port = infos['port'];
proto = infos['proto'];

banner = get_sip_banner( port:port, proto:proto );

if ( ! banner ) exit( 0 );
# Sample: Sip EXpress router (0.8.12 (i386/linux))

if( egrep( pattern:"Sip EXpress router .(0\.[0-7]\.|0\.8\.[0-9]|0\.8\.10) ", string:banner, icase:TRUE ) ) {
  security_message( port:port, protocol:proto );
  exit( 0 );
}

exit( 99);
