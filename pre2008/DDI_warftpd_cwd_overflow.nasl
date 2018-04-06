# OpenVAS Vulnerability Test
# $Id: DDI_warftpd_cwd_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: War FTP Daemon CWD/MKD Buffer Overflow
#
# Authors:
# Erik Tayler <erik@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2003 Digital Defense, Inc.
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
#

tag_summary = "The version of the War FTP Daemon running on this host is vulnerable to a
buffer overflow attack. This is due to improper bounds checking within the
code that handles both the CWD and MKD commands. By exploiting this 
vulnerability, it is possible to crash the server, and potentially run 
arbitrary commands on this system.";

tag_solution = "Visit the following link and download the latest version of WarFTPd:

ftp://ftp.jgaa.com/pub/products/Windows/WarFtpDaemon/";


if(description)
{
	script_oid("1.3.6.1.4.1.25623.1.0.11205");
	script_version("$Revision: 9348 $");
	script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
	script_bugtraq_id(966);
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
	
	script_cve_id("CVE-2000-0131");

	name = "War FTP Daemon CWD/MKD Buffer Overflow";
	script_name(name);

	summary = "War FTP Daemon CWD/MKD Buffer Overflow";
	script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
	script_copyright("This script is Copyright (C) 2003 Digital Defense, Inc.");
	family = "FTP";
	script_family(family);
	script_require_ports("Services/ftp", 21);
	script_dependencies("find_service_3digits.nasl");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
	exit(0);
}


include("ftp_func.inc");

port = get_kb_item("Services/ftp");

if(!port)port = 21;

if(get_port_state(port))
{
	r = get_ftp_banner(port:port);
	if(!r)exit(0);
	
	if(("WAR-FTPD 1.66x4" >< r) || ("WAR-FTPD 1.67-03" >< r))
	{
		security_message(port);
	}
}
