# OpenVAS Vulnerability Test
# $Id: openssh_channel.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: OpenSSH Channel Code Off by 1
#
# Authors:
# Thomas reinke <reinke@e-softinc.com>
#
# Copyright:
# Copyright (C) 2002 Thomas Reinke
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

tag_summary = "You are running a version of OpenSSH which is older than 3.1.

Versions prior than 3.1 are vulnerable to an off by one error
that allows local users to gain root access, and it may be
possible for remote users to similarly compromise the daemon
for remote access.

In addition, a vulnerable SSH client may be compromised by
connecting to a malicious SSH daemon that exploits this
vulnerability in the client code, thus compromising the
client system.";

tag_solution = "Upgrade to OpenSSH 3.1 or apply the patch for
prior versions. (See: http://www.openssh.org)";

if(description)
{
 	script_id(10883);
 	script_version("$Revision: 6056 $");
 	script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
 	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 	script_bugtraq_id(4241);
    script_tag(name:"cvss_base", value:"10.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
	script_cve_id("CVE-2002-0083");
 	name = "OpenSSH Channel Code Off by 1";
	script_name(name);
 

 
 	summary = "Checks for the remote OpenSSH version";
 
 	script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
 
 
 	script_copyright("This script is Copyright (c) 2002 Thomas Reinke");
  	
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


banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

if(ereg(pattern:"ssh-.*-openssh[-_](2\..*|3\.0).*" , string:tolower(banner)))
		security_message(port);
