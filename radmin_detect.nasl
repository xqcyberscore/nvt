# OpenVAS Vulnerability Test
# $Id: radmin_detect.nasl 4034 2016-09-12 12:12:26Z cfi $
# Description: radmin detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "radmin is running on this port. 
Make sure that you use a strong password, otherwise a cracker
may brute-force it and control your machine.

If you did not install this on the computer, you may have
been hacked into.
See: http://www.secnap.com/security/radmin001.html";

tag_solution = "disable it if you do not use it";

if(description)
{
  script_id(11123);
  script_version("$Revision: 4034 $");
  script_tag(name:"last_modification", value:"$Date: 2016-09-12 14:12:26 +0200 (Mon, 12 Sep 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("radmin detection");
  script_summary("Detect radmin");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Malware");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 4899);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include ("misc_func.inc");

port = get_unknown_port( default:4899 );

soc = open_sock_tcp(port);
if (! soc) exit(0);

req = raw_string(0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x08);
send(socket: soc, data: req);
#r = recv(socket: soc, length: 16);
r = recv(socket: soc, length: 6);
close(soc);

# I got :
# 0000000 001  \0  \0  \0   %  \0  \0 001 020  \b 001  \0  \0  \b  \0  \0
#         01 00 00 00 25 00 00 01 10 08 01 00 00 08 00 00
# 0000020  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0
#         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
# 0000040  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0
#         00 00 00 00 00 00 00 00 00 00 00 00 00 00
# 0000056
#
# Noam Rathaus <noamr@beyondsecurity.com> saw differents replies,
# depending on the security settings:
#  password security => 6th byte (r[5]) == 0
#  NTLM security     => 6th byte (r[5]) == 1
# I tried, and always got the same answer, whatever the security setting is.
# Odd...
# 

#xp = raw_string(0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x01, 
#                0x10, 0x08, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00);

xp1 = "010000002500";
xp2 = "010000002501";


if (( xp1 >< hexstr(r) ) || ( xp2 >< hexstr(r) ))
{
        log_message(port);
        register_service(port: port, proto: "radmin");
	exit(0);
}
