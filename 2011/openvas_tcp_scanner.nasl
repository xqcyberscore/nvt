###############################################################################
# OpenVAS Vulnerability Test
# $Id: openvas_tcp_scanner.nasl 7006 2017-08-25 11:51:20Z teissa $
#
# Wrapper for calling built-in NVT "openvas_tcp_scanner" which was previously
# a binary ".nes".
#
# Authors:
# Jan-Oliver Wagner <Jan-Oliver.Wagner@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if (description)
{
 script_id(10335);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 7006 $");
 script_tag(name:"last_modification", value:"$Date: 2017-08-25 13:51:20 +0200 (Fri, 25 Aug 2017) $");
 script_tag(name:"creation_date", value:"2011-01-14 10:12:23 +0100 (Fri, 14 Jan 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("OpenVAS TCP scanner");
 script_tag(name:"qod_type", value:"general_note");
 script_category(ACT_SCANNER);
 script_family("Port scanners");
 script_copyright("(C) 2004 Michel Arboi <mikhail@nessus.org>");

 script_dependencies("ping_host.nasl");

 script_timeout(4*360);

 script_tag(name : "summary" , value : "This plugin is a classical TCP port scanner
It shall be reasonably quick even against a firewalled target.

Once a TCP connection is open, it grabs any available banner
for the service identification plugins

Note that TCP scanners are more intrusive than
SYN (half open) scanners.");
 exit(0);
}

plugin_run_openvas_tcp_scanner();
