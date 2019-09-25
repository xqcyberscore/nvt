###############################################################################
# OpenVAS Vulnerability Test
#
# NTP mode 7 MODE_PRIVATE Packet Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100399");
  script_version("2019-09-24T10:41:39+0000");
  script_bugtraq_id(37255);
  script_cve_id("CVE-2009-3563");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-24 10:41:39 +0000 (Tue, 24 Sep 2019)");
  script_tag(name:"creation_date", value:"2009-12-15 19:11:56 +0100 (Tue, 15 Dec 2009)");
  script_name("NTP mode 7 MODE_PRIVATE Packet Remote Denial of Service Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ntp_open.nasl");
  script_require_udp_ports("Services/udp/ntp", 123);
  script_mandatory_keys("ntp/remote/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37255");
  script_xref(name:"URL", value:"https://support.ntp.org/bugs/show_bug.cgi?id=1331");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/568372");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"NTP.org's ntpd is prone to a remote denial-of-service vulnerability because it
  fails to properly handle certain incoming network packets.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause the application to consume
  excessive CPU resources and fill disk space with log messages.");

  script_tag(name:"vuldetect", value:"Send a NTP mode 7 request and check the response.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service(default:123, ipproto:"udp", proto:"ntp");

soc = open_sock_udp(port);
if(!soc)
  exit(0);

data = raw_string(0x97, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00);
send(socket:soc, data:data);
r = recv(socket:soc, length:8);
close(soc);

if(!r)
  exit(0);

if(hexstr(r) == "9700000030000000") {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);
