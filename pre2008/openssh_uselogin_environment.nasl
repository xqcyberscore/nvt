# OpenVAS Vulnerability Test
# $Id: openssh_uselogin_environment.nasl 3445 2016-06-07 08:35:53Z mime $
# Description: OpenSSH UseLogin Environment Variables
#
# Authors:
# EMAZE Networks S.p.A.
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
# changes by rd: description, static report
#
# Copyright:
# Copyright (C) 2001 EMAZE Networks S.p.A.
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

tag_summary = "You are running a version of OpenSSH which is older than 3.0.2.

Versions prior than 3.0.2 are vulnerable to an environment
variables export that can allow a local user to execute
command with root privileges.
This problem affect only versions prior than 3.0.2, and when
the UseLogin feature is enabled (usually disabled by default)";

tag_solution = "Upgrade to OpenSSH 3.0.2 or apply the patch for prior
versions. (Available at: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH)";

if(description)
{
 	script_id(10823);
 	script_version("$Revision: 3445 $");
 	script_tag(name:"last_modification", value:"$Date: 2016-06-07 10:35:53 +0200 (Tue, 07 Jun 2016) $");
 	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 	script_bugtraq_id(3614);
	script_xref(name:"IAVA", value:"2001-t-0017");
	script_cve_id("CVE-2001-0872");
    script_tag(name:"cvss_base", value:"7.2");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 	name = "OpenSSH UseLogin Environment Variables";
	script_name(name);
 

 
 	summary = "Checks for the remote SSH version";
 	script_summary(summary);
 
 	script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
 
 
 	script_copyright("This script is copyright (C) 2001 by EMAZE Networks S.p.A.");
  	
	family = "Gain a shell remotely";
 	script_family(family);
 	
	script_dependencies("ssh_detect.nasl");
 	script_require_ports("Services/ssh", 22);
 
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
 	exit(0);
}


#
# The script code starts here
#

port = get_kb_item("Services/ssh");
if(!port) port = 22;

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);

if(ereg(pattern:"ssh-.*-openssh[-_](1\..*|2\..*|3\.0.[0-1]).*" , string:tolower(banner))) 
	{
		security_message(port);
	}
